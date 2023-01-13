// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-clusterpool-v2")

// Allocator implements allocator.AllocatorProvider
type Allocator struct {
	poolAlloc *PoolAllocator
}

type poolSpec struct {
	ipv4CIDRs    []string
	ipv6CIDRs    []string
	ipv4MaskSize int
	ipv6MaskSize int
}

const (
	poolKeyIPv4CIDRs    = "ipv4-cidrs"
	poolKeyIPv4MaskSize = "ipv4-mask-size"
	poolKeyIPv6CIDRs    = "ipv6-cidrs"
	poolKeyIPv6MaskSize = "ipv6-mask-size"
)

// parsePoolSpec parses a pool spec string in the form
// "ipv4-cidrs:172.16.0.0/16,172.17.0.0/16;ipv4-mask-size:24".
func parsePoolSpec(poolString string) (poolSpec, error) {
	fields := strings.Split(strings.ReplaceAll(poolString, " ", ""), ";")

	var pool poolSpec
	for _, field := range fields {
		kv := strings.Split(field, ":")
		if len(kv) != 2 {
			return pool, fmt.Errorf("invalid number of key delimiters in pool spec %s", poolString)
		}
		switch kv[0] {
		case poolKeyIPv4CIDRs:
			pool.ipv4CIDRs = strings.Split(kv[1], ",")
			// TODO: validate individual CIDRs?
		case poolKeyIPv4MaskSize:
			mask, err := strconv.Atoi(kv[1])
			if err != nil {
				return pool, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			pool.ipv4MaskSize = mask
		case poolKeyIPv6CIDRs:
			pool.ipv6CIDRs = strings.Split(kv[1], ",")
		case poolKeyIPv6MaskSize:
			mask, err := strconv.Atoi(kv[1])
			if err != nil {
				return pool, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			pool.ipv6MaskSize = mask
		}
	}
	return pool, nil
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

	// TODO: make this configurable by CLI flag?
	poolDefault := "default"

	for poolName, pool := range operatorOption.Config.IPAMClusterPoolMap {
		log.WithFields(logrus.Fields{
			"pool-name": poolName,
			"pool":      pool,
		}).Debug("found pool definition")

		if poolName == poolDefault {
			return fmt.Errorf("cannot re-define %s pool in %s", poolDefault, operatorOption.IPAMClusterPoolMap)
		}

		pool, err := parsePoolSpec(pool)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"pool-name": poolName,
				"pool":      pool,
			}).Debug("failed to parse pool spec")
			// TODO: multierr?
			return fmt.Errorf("failed to parse pool spec for pool %s: %w", poolName, err)
		}

		log.WithFields(logrus.Fields{
			"pool-name":     poolName,
			"ipv4-cidrs":    pool.ipv4CIDRs,
			"ipv4-masksize": pool.ipv4MaskSize,
			"ipv6-cidrs":    pool.ipv6CIDRs,
			"ipv6-masksize": pool.ipv6MaskSize,
		}).Debug("adding pool")
		if err := a.poolAlloc.AddPool(poolName, pool.ipv4CIDRs, pool.ipv4MaskSize, pool.ipv6CIDRs, pool.ipv6MaskSize); err != nil {
			log.WithError(err).WithField("pool", pool).Debug("failed to add pool")
			// TODO: multierr?
			return err
		}
	}
	return a.poolAlloc.AddPool(poolDefault, defaultIPv4CIDRs, defaultIPv4MaskSize, defaultIPv6CIDRs, defaultIPv6MaskSize)
}

func (a *Allocator) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	return NewNodeHandler(a.poolAlloc, getterUpdater), nil
}
