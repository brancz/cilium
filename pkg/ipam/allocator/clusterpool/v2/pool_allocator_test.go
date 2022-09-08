package v2

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestPoolAllocator_AllocateToNode(t *testing.T) {
	type fields struct {
		pools map[string]cidrPool
		nodes map[string]poolToCIDRs
		ready bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    *v2.CiliumNode
		want    *v2.CiliumNode
		wantErr bool
	}{
		{
			name: "empty pool",
			fields: fields{
				pools: map[string]cidrPool{
					"default": {
						v4: nil,
						v6: nil,
					},
				},
				ready: true,
			},
			args: &v2.CiliumNode{
				Spec: v2.NodeSpec{
					IPAM: ipamTypes.IPAMSpec{
						Pools: ipamTypes.IPAMPoolSpec{
							Requested: []ipamTypes.IPAMPoolRequest{
								{
									Pool: "default",
									Needed: ipamTypes.IPAMPoolDemand{
										IPv4Addrs: 10,
										IPv6Addrs: 10,
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PoolAllocator{
				pools: tt.fields.pools,
				nodes: tt.fields.nodes,
				ready: tt.fields.ready,
			}
			if err := p.AllocateToNode(tt.args); (err != nil) != tt.wantErr {
				t.Errorf("AllocateToNode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want != nil {
				p.PopulateNodeSpec(tt.args)
				if diff := cmp.Diff(tt.args, tt.want); diff != "" {
					t.Errorf("AllocateToNode() diff = %s", diff)
				}
			}
		})
	}
}
