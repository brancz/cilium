package ipam

import (
	"context"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/trigger"
)

const defaultPool = "default"

type poolPair struct {
	v4 *podCIDRPool
	v6 *podCIDRPool
}

type clusterPoolManager struct {
	mutex *lock.Mutex
	conf  Configuration
	owner Owner

	pools        map[string]*poolPair
	poolsUpdated chan struct{}

	node *ciliumv2.CiliumNode

	controller  *controller.Manager
	k8sUpdater  *trigger.Trigger
	nodeUpdater nodeUpdater

	finishedRestore bool
}

var _ Allocator = (*clusterPoolManager)(nil)

func newClusterPoolManager(conf Configuration, nodeWatcher nodeWatcher, owner Owner, nodeUpdater nodeUpdater) *clusterPoolManager {
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
		pools:           map[string]*poolPair{},
		poolsUpdated:    make(chan struct{}, 1),
		node:            nil,
		controller:      k8sController,
		k8sUpdater:      k8sUpdater,
		nodeUpdater:     nodeUpdater,
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

	// initialize pod CIDR pools from existing or new CiliumNode CRD
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

func (c *clusterPoolManager) updateCiliumNode(ctx context.Context) error {
	c.mutex.Lock()
	node := c.node.DeepCopy()
	spec := []types.IPAMPoolRequest{}
	status := []types.IPAMPoolStatus{}
	for poolName, pool := range c.pools {
		cidrs := types.PodCIDRMap{}
		var neededIPv4, neededIPv6 int

		// TODO how about pools that don't exist yet???

		if pool.v4 != nil {
			var cidrsIPv4 types.PodCIDRMap
			//neededIPv4, cidrsIPv4 = pool.v4.clusterPoolV2Beta2(8, 16)
			maps.Copy(cidrs, cidrsIPv4)
		}
		if pool.v6 != nil {
			var cidrsIPv6 types.PodCIDRMap
			//neededIPv6, cidrsIPv6 = pool.v6.clusterPoolV2Beta2(8, 16)
			maps.Copy(cidrs, cidrsIPv6)
		}

		spec = append(spec, types.IPAMPoolRequest{
			Pool: poolName,
			Needed: types.IPAMPoolDemand{
				IPv4Addrs: neededIPv4,
				IPv6Addrs: neededIPv6,
			},
		})

		status = append(status, types.IPAMPoolStatus{
			Pool:  poolName,
			CIDRs: nil,
		})
	}
	node.Spec.IPAM.Pools.Requested = spec
	node.Status.IPAM.Pools = status
	c.mutex.Unlock()

	return nil
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

func (c *clusterPoolManager) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	//TODO implement me
	panic("implement me")
}

func (c *clusterPoolManager) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	//TODO implement me
	panic("implement me")
}

func (c *clusterPoolManager) Release(ip net.IP, pool Pool) error {
	//TODO implement me
	panic("implement me")
}

func (c *clusterPoolManager) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	//TODO implement me
	panic("implement me")
}

func (c *clusterPoolManager) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	//TODO implement me
	panic("implement me")
}

func (c *clusterPoolManager) Dump() (map[string]string, string) {
	//TODO implement me
	panic("implement me")
}

func (c *clusterPoolManager) RestoreFinished() {
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
