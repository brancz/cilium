// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"context"
	"fmt"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-clusterpool-v2")

// Allocator implements allocator.AllocatorProvider
type Allocator struct {
	poolAlloc *PoolAllocator
}

func (a *Allocator) Init(ctx context.Context) error {
	a.poolAlloc = NewPoolAllocator()

	var defaultIPv4CIDRs, defaultIPv6CIDRs []string
	var defaultIPv4MaskSize, defaultIPv6MaskSize int
	if option.Config.EnableIPv4 {
		if len(operatorOption.Config.ClusterPoolIPv4CIDR) == 0 {
			return fmt.Errorf("%s must be provided when using ClusterPool", operatorOption.ClusterPoolIPv4CIDR)
		}
		defaultIPv4CIDRs = operatorOption.Config.ClusterPoolIPv4CIDR
		defaultIPv4MaskSize = operatorOption.Config.NodeCIDRMaskSizeIPv4
	} else if len(operatorOption.Config.ClusterPoolIPv4CIDR) != 0 {
		return fmt.Errorf("%s must not be set if IPv4 is disabled", operatorOption.ClusterPoolIPv4CIDR)
	}

	if option.Config.EnableIPv6 {
		if len(operatorOption.Config.ClusterPoolIPv6CIDR) == 0 {
			return fmt.Errorf("%s must be provided when using ClusterPool", operatorOption.ClusterPoolIPv6CIDR)
		}
		defaultIPv6CIDRs = operatorOption.Config.ClusterPoolIPv6CIDR
		defaultIPv6MaskSize = operatorOption.Config.NodeCIDRMaskSizeIPv6
	} else if len(operatorOption.Config.ClusterPoolIPv6CIDR) != 0 {
		return fmt.Errorf("%s must not be set if IPv6 is disabled", operatorOption.ClusterPoolIPv6CIDR)
	}

	return a.poolAlloc.AddPool("default", defaultIPv4CIDRs, defaultIPv4MaskSize, defaultIPv6CIDRs, defaultIPv6MaskSize)
}

func (a *Allocator) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	return NewNodeHandler(a.poolAlloc, getterUpdater), nil
}
