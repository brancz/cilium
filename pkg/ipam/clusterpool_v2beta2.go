package ipam

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

const defaultPool = "default"

type poolPair struct {
	v4 *podCIDRPool
	v6 *podCIDRPool
}

type preAllocValue int
type preAllocMap map[string]preAllocValue

func parsePreAllocMap(conf map[string]string) (preAllocMap, error) {
	m := make(map[string]preAllocValue, len(conf))
	for pool, s := range conf {
		value, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid pre-alloc value for pool %q: %w", pool, err)
		}
		m[pool] = preAllocValue(value)
	}

	return m, nil
}

type clusterPoolManager struct {
	mutex *lock.Mutex
	conf  Configuration
	owner Owner

	preallocMap  preAllocMap
	pools        map[string]*poolPair
	poolsUpdated chan struct{}

	node *ciliumv2.CiliumNode

	controller  *controller.Manager
	k8sUpdater  *trigger.Trigger
	nodeUpdater nodeUpdater

	finishedRestore bool
}

var _ Allocator = (*clusterPoolV2Allocator)(nil)

func newClusterPoolManager(conf Configuration, nodeWatcher nodeWatcher, owner Owner, clientset client.Clientset) *clusterPoolManager {
	preallocMap, err := parsePreAllocMap(option.Config.IPAMClusterPoolNodePreAlloc)
	if err != nil {
		log.WithError(err).Fatalf("Invalid %s flag value", option.IPAMClusterPoolNodePreAlloc)
	}

	k8sController := controller.NewManager()
	k8sUpdater, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 15 * time.Second,
		TriggerFunc: func(reasons []string) {
			// this is a no-op before controller is instantiated in restoreFinished
			k8sController.TriggerController(clusterPoolStatusControllerName)
		},
		Name: clusterPoolStatusTriggerName,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}

	c := &clusterPoolManager{
		mutex:           &lock.Mutex{},
		owner:           owner,
		conf:            conf,
		preallocMap:     preallocMap,
		pools:           map[string]*poolPair{},
		poolsUpdated:    make(chan struct{}, 1),
		node:            nil,
		controller:      k8sController,
		k8sUpdater:      k8sUpdater,
		nodeUpdater:     clientset.CiliumV2().CiliumNodes(),
		finishedRestore: false,
	}

	// Subscribe to CiliumNode updates
	nodeWatcher.RegisterCiliumNodeSubscriber(c)
	owner.UpdateCiliumNodeResource()

	return c
}

func (c *clusterPoolManager) waitForPool(ctx context.Context, family Family, poolName string) {
	timer, stop := inctimer.New()
	defer stop()
	for {
		c.mutex.Lock()
		switch family {
		case IPv4:
			if p, ok := c.pools[poolName]; ok && p.v4.hasAvailableIPs() {
				return
			}
		case IPv6:
			if p, ok := c.pools[poolName]; ok && p.v6.hasAvailableIPs() {
				return
			}
		}
		c.mutex.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-c.poolsUpdated:
			continue
		case <-timer.After(5 * time.Second):
			log.WithFields(logrus.Fields{
				logfields.HelpMessage: "Check if cilium-operator pod is running and does not have any warnings or error messages.",
				logfields.Family:      family,
			}).Info("Waiting for pod CIDR pool to become available")
		}
	}
}

func (c *clusterPoolManager) localAllocCIDRsLocked() (ipv4, ipv6 []*cidr.CIDR) {
	// first default pool CIDR is supposed to be the primary CIDR
	if pool, ok := c.pools[defaultPool]; ok {
		if pool.v4 != nil {
			ipv4 = append(ipv4, pool.v4.availablePodCIDRs()...)
		}
		if pool.v6 != nil {
			ipv6 = append(ipv6, pool.v6.availablePodCIDRs()...)
		}
	}

	// TODO: Should we really have a route for alternate pools?
	for poolName, pool := range c.pools {
		if poolName == defaultPool {
			continue
		}
		if pool.v4 != nil {
			ipv4 = append(ipv4, pool.v4.availablePodCIDRs()...)
		}
		if pool.v6 != nil {
			ipv6 = append(ipv6, pool.v6.availablePodCIDRs()...)
		}
	}

	return ipv4, ipv6
}

func (c *clusterPoolManager) ciliumNodeUpdated(newNode *ciliumv2.CiliumNode) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// restore state from previous agent run, this collects (previously)
	// released CIDRs and ensures they are not used for allocation in this instance either
	if c.node == nil {
		for _, pool := range newNode.Status.IPAM.Pools {
			c.initPoolLocked(pool)
		}
	}

	for _, pool := range newNode.Spec.IPAM.Pools.Allocated {
		c.upsertPoolLocked(pool.Pool, pool.CIDRs)
	}

	c.owner.LocalAllocCIDRsUpdated(c.localAllocCIDRsLocked())
	c.node = newNode
}

func neededIPCeil(numIP int, preAlloc int) int {
	quotient := numIP / preAlloc
	rem := numIP % preAlloc
	if rem > 0 {
		return (quotient + 2) * preAlloc
	}
	return (quotient + 1) * preAlloc
}

func (c *clusterPoolManager) updateCiliumNode(ctx context.Context) error {
	c.mutex.Lock()
	newNode := c.node.DeepCopy()
	spec := []types.IPAMPoolRequest{}
	status := []types.IPAMPoolStatus{}

	// Only pools present in cluster-pool-node-pre-alloc can be requested
	for poolName, preAlloc := range c.preallocMap {
		var neededIPv4, neededIPv6 int
		pool, ok := c.pools[poolName]
		if ok {
			if pool.v4 != nil {
				neededIPv4 = pool.v4.inUseIPCount()
			}
			if pool.v6 != nil {
				neededIPv6 = pool.v6.inUseIPCount()
			}
		}

		// Always round up to pre-alloc value
		neededIPv4 = neededIPCeil(neededIPv4, int(preAlloc))
		neededIPv6 = neededIPCeil(neededIPv6, int(preAlloc))

		if ok {
			s := types.IPAMPoolStatus{
				Pool:  poolName,
				CIDRs: map[string]types.PodCIDRMapEntry{},
			}

			for releasedCIDR := range pool.v4.releaseExcessCIDRsV2(neededIPv4) {
				s.CIDRs[releasedCIDR] = types.PodCIDRMapEntry{Status: types.PodCIDRStatusReleased}
			}
			for releasedCIDR := range pool.v6.releaseExcessCIDRsV2(neededIPv6) {
				s.CIDRs[releasedCIDR] = types.PodCIDRMapEntry{Status: types.PodCIDRStatusReleased}
			}

			if len(s.CIDRs) > 0 {
				status = append(status, s)
			}
		}

		spec = append(spec, types.IPAMPoolRequest{
			Pool: poolName,
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: neededIPv4,
				IPv6Addrs: neededIPv6,
			},
		})
	}
	sort.Slice(spec, func(i, j int) bool {
		return spec[i].Pool > spec[j].Pool
	})
	sort.Slice(status, func(i, j int) bool {
		return status[i].Pool > status[j].Pool
	})

	newNode.Spec.IPAM.Pools.Requested = spec
	newNode.Status.IPAM.Pools = status

	needsSpecUpdate := !newNode.Spec.IPAM.DeepEqual(&c.node.Spec.IPAM)
	needsStatusUpdate := !newNode.Status.IPAM.DeepEqual(&c.node.Status.IPAM)

	c.mutex.Unlock()

	// TODO: Validate that this order of updates is safe with regard to CIDRs
	// referred to in Spec vs Status. Especially need to check that the status
	// update triggers the cilium-operator to re-check the spec (in case CIDRs
	// were released)

	var controllerErr error
	if needsSpecUpdate {
		_, err := c.nodeUpdater.Update(ctx, newNode, metav1.UpdateOptions{})
		if err != nil {
			controllerErr = multierr.Append(controllerErr, fmt.Errorf("failed to update node spec: %w", err))
		}
	}

	if needsStatusUpdate {
		_, err := c.nodeUpdater.UpdateStatus(ctx, newNode, metav1.UpdateOptions{})
		if err != nil {
			controllerErr = multierr.Append(controllerErr, fmt.Errorf("failed to update node status: %w", err))
		}
	}

	// TODO: Should we refetch c.node if controllerErr != nil
	return controllerErr
}

func (c *clusterPoolManager) initPoolLocked(pool types.IPAMPoolStatus) {
	var releasedIPv4PodCIDRs, releasedIPv6PodCIDRs []string

	for podCIDR, s := range pool.CIDRs {
		if s.Status == types.PodCIDRStatusReleased {
			switch podCIDRFamily(podCIDR) {
			case IPv4:
				releasedIPv4PodCIDRs = append(releasedIPv4PodCIDRs, podCIDR)
			case IPv6:
				releasedIPv6PodCIDRs = append(releasedIPv6PodCIDRs, podCIDR)
			}
		}
	}

	var ipv4Pool, ipv6Pool *podCIDRPool
	if c.conf.IPv4Enabled() {
		ipv4Pool = newPodCIDRPool(releasedIPv4PodCIDRs)
	}
	if c.conf.IPv6Enabled() {
		ipv6Pool = newPodCIDRPool(releasedIPv6PodCIDRs)
	}

	c.pools[pool.Pool] = &poolPair{
		v4: ipv4Pool,
		v6: ipv6Pool,
	}
}

func (c *clusterPoolManager) upsertPoolLocked(poolName string, podCIDRs []string) {
	pool, ok := c.pools[poolName]
	if !ok {
		pool = &poolPair{}
		if c.conf.IPv4Enabled() {
			pool.v4 = newPodCIDRPool(nil)
		}
		if c.conf.IPv6Enabled() {
			pool.v6 = newPodCIDRPool(nil)
		}
	}

	var ipv4PodCIDRs, ipv6PodCIDRs []string
	for _, podCIDR := range podCIDRs {
		switch podCIDRFamily(podCIDR) {
		case IPv4:
			ipv4PodCIDRs = append(ipv4PodCIDRs, podCIDR)
		case IPv6:
			ipv6PodCIDRs = append(ipv6PodCIDRs, podCIDR)
		}
	}

	pool.v4.updatePool(ipv4PodCIDRs)
	pool.v6.updatePool(ipv6PodCIDRs)

	select {
	case c.poolsUpdated <- struct{}{}:
	default:
	}
}

func (c *clusterPoolManager) OnAddCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		c.ciliumNodeUpdated(node)
	}

	return nil
}

func (c *clusterPoolManager) OnUpdateCiliumNode(oldNode, newNode *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(newNode) {
		c.ciliumNodeUpdated(newNode)
	}

	return nil
}

func (c *clusterPoolManager) OnDeleteCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		log.WithField(logfields.Node, node).Warning("Local CiliumNode deleted. IPAM will continue on last seen version")
	}

	return nil
}

func (c *clusterPoolManager) restoreFinished() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.finishedRestore {
		return
	}

	// creating a new controller will execute DoFunc immediately
	c.controller.UpdateController(clusterPoolStatusControllerName, controller.ControllerParams{
		DoFunc: c.updateCiliumNode,
	})
	c.finishedRestore = true
}

func (c *clusterPoolManager) poolByFamilyLocked(poolName string, family Family) *podCIDRPool {
	switch family {
	case IPv4:
		pair, ok := c.pools[poolName]
		if ok {
			return pair.v4
		}
	case IPv6:
		pair, ok := c.pools[poolName]
		if ok {
			return pair.v6
		}
	}

	return nil
}

func (c *clusterPoolManager) allocateNext(owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	pool := c.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return nil, fmt.Errorf("unable to allocate from unknown pool %q (family %s)", poolName, family)
	}

	ip, err := pool.allocateNext()
	if err != nil {
		return nil, err
	}

	if syncUpstream {
		c.k8sUpdater.TriggerWithReason("allocation of next IP")
	}
	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolManager) allocateIP(ip net.IP, owner string, poolName Pool, family Family, syncUpstream bool) (*AllocationResult, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	pool := c.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return nil, fmt.Errorf("unable to reserve IP %s from unknown pool %q (family %s)", ip, poolName, family)
	}

	err := pool.allocate(ip)
	if err != nil {
		return nil, err
	}

	if syncUpstream {
		c.k8sUpdater.TriggerWithReason("allocation of IP")
	}
	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolManager) releaseIP(ip net.IP, poolName Pool, family Family) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	pool := c.poolByFamilyLocked(poolName.String(), family)
	if pool == nil {
		return fmt.Errorf("unable to release IP %s of unknown pool %q (family %s)", ip, poolName, family)
	}

	err := pool.release(ip)
	if err == nil {
		c.k8sUpdater.TriggerWithReason("release of IP")
	}
	return err
}

func (c *clusterPoolManager) Allocator(family Family) Allocator {
	return &clusterPoolV2Allocator{
		manager: c,
		family:  family,
	}
}

type clusterPoolV2Allocator struct {
	manager *clusterPoolManager
	family  Family
}

func (c *clusterPoolV2Allocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, true)
}

func (c *clusterPoolV2Allocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, false)
}

func (c *clusterPoolV2Allocator) Release(ip net.IP, pool Pool) error {
	return c.manager.releaseIP(ip, pool, c.family)
}

func (c *clusterPoolV2Allocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, true)
}

func (c *clusterPoolV2Allocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, false)
}

func (c *clusterPoolV2Allocator) Dump() (map[string]string, string) {
	//TODO implement me
	return nil, "implement me"
}

func (c *clusterPoolV2Allocator) RestoreFinished() {
	c.manager.restoreFinished()
}
