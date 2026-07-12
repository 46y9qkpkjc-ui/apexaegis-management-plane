package gateway

import (
	"reflect"
	"testing"
)

func TestApplyCapabilitiesFromMetadata(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]string
		want GatewayNode
	}{
		{
			name: "legacy defaults (no metadata)",
			meta: nil,
			want: GatewayNode{DataPlane: "ip-over-quic"},
		},
		{
			name: "stream-proxy bonded",
			meta: map[string]string{
				"data_plane":            "stream-proxy",
				"alpn":                  "apexaegis-mpquic",
				"supports_bonding":      "true",
				"supports_tcp_fallback": "true",
				"egress_ips":            "1.2.3.4, 1.2.3.5 ,",
			},
			want: GatewayNode{
				DataPlane:           "stream-proxy",
				ALPN:                "apexaegis-mpquic",
				SupportsBonding:     true,
				SupportsTCPFallback: true,
				EgressIPs:           []string{"1.2.3.4", "1.2.3.5"},
			},
		},
		{
			name: "stream-proxy no bonding",
			meta: map[string]string{"data_plane": "stream-proxy", "alpn": "apexaegis-mpquic"},
			want: GatewayNode{DataPlane: "stream-proxy", ALPN: "apexaegis-mpquic"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &GatewayNode{Metadata: c.meta}
			n.applyCapabilitiesFromMetadata()
			got := GatewayNode{
				DataPlane:           n.DataPlane,
				ALPN:                n.ALPN,
				SupportsBonding:     n.SupportsBonding,
				SupportsTCPFallback: n.SupportsTCPFallback,
				EgressIPs:           n.EgressIPs,
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v want %+v", got, c.want)
			}
		})
	}
}
