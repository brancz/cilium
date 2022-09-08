// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"fmt"
	"math"
	"net/netip"
	"sort"

	"go.uber.org/multierr"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
	"github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
)

type cidrPool struct {
	v4 []cidralloc.CIDRAllocator
	v6 []cidralloc.CIDRAllocator
}

type cidrSet map[netip.Prefix]struct{}

func (c cidrSet) StringSlice() []string {
	cidrs := make([]string, 0, len(c))
	for cidr := range c {
		cidrs = append(cidrs, cidr.String())
	}
	sort.Strings(cidrs)
	return cidrs
}

// availableAddrBits returns the log2(availableIPs) of this CIDR set
func (c cidrSet) availableAddrBits() int {
	bits := 0
	for p := range c {
		bits += p.Addr().BitLen() - p.Bits()
	}
	return bits
}

type cidrSets struct {
	v4 cidrSet
	v6 cidrSet
}

type poolToCIDRs map[string]cidrSets // poolName -> list of allocated CIDRs

type errAllocatorNotReady struct{}

var ErrAllocatorNotReady = errAllocatorNotReady{}

func (m errAllocatorNotReady) Error() string {
	return "allocator not ready"
}

func (m errAllocatorNotReady) Is(target error) bool {
	return target == ErrAllocatorNotReady
}

type PoolAllocator struct {
	pools map[string]cidrPool    // poolName -> pool
	nodes map[string]poolToCIDRs // nodeName -> pool -> cidrs
	ready bool
}

func NewPoolAllocator() *PoolAllocator {
	return &PoolAllocator{
		pools: map[string]cidrPool{},
		nodes: map[string]poolToCIDRs{},
	}
}

func (p *PoolAllocator) RestoreFinished() {
	p.ready = true
}

func (p *PoolAllocator) AddPool(poolName string, ipv4CIDRs []string, ipv4MaskSize int, ipv6CIDRs []string, ipv6MaskSize int) error {
	if _, ok := p.pools[poolName]; ok {
		return fmt.Errorf("pool %q already exists", poolName)
	}

	v4, err := cidralloc.NewCIDRSets(false, ipv4CIDRs, ipv4MaskSize)
	if err != nil {
		return err
	}

	v6, err := cidralloc.NewCIDRSets(true, ipv6CIDRs, ipv6MaskSize)
	if err != nil {
		return err
	}

	p.pools[poolName] = cidrPool{
		v4: v4,
		v6: v6,
	}

	return nil
}

func (p *PoolAllocator) AllocateToNode(cn *v2.CiliumNode) error {
	// We first need to check for CIDRs which we want to occupy, i.e. mark as
	// allocated to the node. This needs to happen before allocations, to avoid
	// handing out the same CIDR twice.
	var err error

	for _, allocatedPool := range cn.Spec.IPAM.Pools.Allocated {
		for _, cidrStr := range allocatedPool.CIDRs {
			prefix, parseErr := netip.ParsePrefix(cidrStr)
			if parseErr != nil {
				err = multierr.Append(err,
					fmt.Errorf("failed to parse CIDR of pool %q: %w", allocatedPool.Pool, parseErr))
				continue
			}

			occupyErr := p.occupyCIDR(cn.Name, allocatedPool.Pool, prefix)
			if occupyErr != nil {
				err = multierr.Append(err, occupyErr)
			}
		}
	}

	for _, poolStatus := range cn.Status.IPAM.Pools {
		for cidrStr, st := range poolStatus.CIDRs {
			prefix, parseErr := netip.ParsePrefix(cidrStr)
			if parseErr != nil {
				err = multierr.Append(err,
					fmt.Errorf("failed to parse CIDR of pool %q: %w", poolStatus.Pool, parseErr))
				continue
			}

			// We either release or occupy any CIDR owned by the node. If it's
			// not marked for release, we want to occupy it to avoid handing
			// it out to other nodes
			if st.Status == types.PodCIDRStatusReleased {
				releaseErr := p.releaseCIDR(cn.Name, poolStatus.Pool, prefix)
				if releaseErr != nil {
					err = multierr.Append(err, releaseErr)
				}
			} else {
				occupyErr := p.occupyCIDR(cn.Name, poolStatus.Pool, prefix)
				if occupyErr != nil {
					err = multierr.Append(err, occupyErr)
				}
			}
		}
	}

	// Delay allocation until we have occupied the CIDRs of all existing nodes.
	// The node manager will call us again once it has ensured that all nodes
	// had their CIDRs occupied, after which p.ready will be set to true
	if !p.ready {
		return ErrAllocatorNotReady
	}

	for _, reqPool := range cn.Spec.IPAM.Pools.Requested {
		allocatedCIDRs := p.nodes[cn.Name][reqPool.Pool]

		if option.Config.EnableIPv4 {
			neededIPv4Bits := int(math.Ceil(math.Log2(float64(reqPool.Needed.IPv4Addrs))))
			missingIPv4Bits := neededIPv4Bits - allocatedCIDRs.v4.availableAddrBits()

			allocErr := p.allocateCIDRs(cn.Name, reqPool.Pool, ipam.IPv4, missingIPv4Bits)
			if allocErr != nil {
				err = multierr.Append(err, fmt.Errorf("ipv4: %w", allocErr))
			}
		}
		if option.Config.EnableIPv6 {
			neededIPv6Bits := int(math.Ceil(math.Log2(float64(reqPool.Needed.IPv6Addrs))))
			missingIPv6Bits := neededIPv6Bits - allocatedCIDRs.v6.availableAddrBits()

			allocErr := p.allocateCIDRs(cn.Name, reqPool.Pool, ipam.IPv6, missingIPv6Bits)
			if allocErr != nil {
				err = multierr.Append(err, fmt.Errorf("ipv6: %w", allocErr))
			}
		}
	}
	return err
}

func (p *PoolAllocator) ReleaseNode(nodeName string) error {
	// Release CIDRs back into pools
	var err error
	for poolName, cidrs := range p.nodes[nodeName] {
		pool, ok := p.pools[poolName]
		if !ok {
			err = multierr.Append(err,
				fmt.Errorf("cannot release from non-existing pool: %s", poolName))
			continue
		}

		for cidr := range cidrs.v4 {
			multierr.AppendInto(&err, releaseCIDR(pool.v4, cidr))
		}
		for cidr := range cidrs.v6 {
			multierr.AppendInto(&err, releaseCIDR(pool.v6, cidr))
		}
	}

	// Remove bookkeeping for this node
	delete(p.nodes, nodeName)

	return err
}

func (p *PoolAllocator) PopulateNodeSpec(cn *v2.CiliumNode) {
	var pools []types.IPAMPoolAllocation
	for poolName, cidrs := range p.nodes[cn.Name] {
		v4CIDRs := cidrs.v4.StringSlice()
		v6CIDRs := cidrs.v6.StringSlice()

		pools = append(pools, types.IPAMPoolAllocation{
			Pool:  poolName,
			CIDRs: append(v4CIDRs, v6CIDRs...),
		})
	}

	sort.Slice(pools, func(i, j int) bool {
		return pools[i].Pool < pools[j].Pool
	})

	cn.Spec.IPAM.Pools.Allocated = pools
}

func (p *PoolAllocator) isAllocated(targetNode, sourcePool string, cidr netip.Prefix) bool {
	var found bool
	switch {
	case cidr.Addr().Is4():
		_, found = p.nodes[targetNode][sourcePool].v4[cidr]
	case cidr.Addr().Is6():
		_, found = p.nodes[targetNode][sourcePool].v6[cidr]
	}
	return found
}

func (p *PoolAllocator) markAllocated(targetNode, sourcePool string, cidr netip.Prefix) {
	pools, ok := p.nodes[targetNode]
	if !ok {
		pools = poolToCIDRs{}
		p.nodes[targetNode] = pools
	}

	cidrs, ok := pools[sourcePool]
	if !ok {
		cidrs = cidrSets{
			v4: cidrSet{},
			v6: cidrSet{},
		}
		pools[sourcePool] = cidrs
	}

	switch {
	case cidr.Addr().Is4():
		cidrs.v4[cidr] = struct{}{}
	case cidr.Addr().Is6():
		cidrs.v6[cidr] = struct{}{}
	}
}

func (p *PoolAllocator) markReleased(targetNode, sourcePool string, cidr netip.Prefix) {
	pools, ok := p.nodes[targetNode]
	if !ok {
		return
	}

	cidrs, ok := pools[sourcePool]
	if !ok {
		return
	}

	switch {
	case cidr.Addr().Is4():
		delete(cidrs.v4, cidr)
	case cidr.Addr().Is6():
		delete(cidrs.v6, cidr)
	}

	// remove pool reference if it is now empty
	if len(cidrs.v4) == 0 && len(cidrs.v6) == 0 {
		delete(pools, sourcePool)
	}
}

func (p *PoolAllocator) allocateCIDRs(targetNode, sourcePool string, family ipam.Family, sizeBits int) error {
	pool, ok := p.pools[sourcePool]
	if !ok {
		return fmt.Errorf("cannot allocate from non-existing pool: %s", sourcePool)
	}

	for sizeBits > 0 {
		cidr, err := pool.allocCIDR(family)
		if err != nil {
			return err
		}

		p.markAllocated(targetNode, sourcePool, cidr)
		sizeBits -= cidr.Addr().BitLen() - cidr.Bits()
	}

	return nil
}

func (p *PoolAllocator) occupyCIDR(targetNode, sourcePool string, cidr netip.Prefix) error {
	// avoid allocating CIDRs twice
	if p.isAllocated(targetNode, sourcePool, cidr) {
		return nil
	}

	pool, ok := p.pools[sourcePool]
	if !ok {
		return fmt.Errorf("cannot reuse from non-existing pool: %s", sourcePool)
	}

	err := pool.occupyCIDR(cidr)
	if err != nil {
		return fmt.Errorf("unable to reuse from pool %s: %w", sourcePool, err)
	}

	p.markAllocated(targetNode, sourcePool, cidr)

	return nil
}

func (p *PoolAllocator) releaseCIDR(targetNode, sourcePool string, cidr netip.Prefix) error {
	// do not release CIDRs not allocated to the node
	if !p.isAllocated(targetNode, sourcePool, cidr) {
		return nil
	}

	pool, ok := p.pools[sourcePool]
	if !ok {
		return fmt.Errorf("cannot release from non-existing pool: %s", sourcePool)
	}

	err := pool.releaseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("unable to release from pool %s: %w", sourcePool, err)
	}

	p.markReleased(targetNode, sourcePool, cidr)

	return nil
}
