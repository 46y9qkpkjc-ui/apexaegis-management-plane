package handlers

import (
	"encoding/json"
	"testing"

	"github.com/zcp/management-plane/internal/db"
)

func TestClientConfigToRuntimeProfileUsesRoutingSettings(t *testing.T) {
	config := db.ClientConfigRecord{
		GroupID:             "it-team",
		GroupName:           "IT Team",
		FeaturesSettings:    json.RawMessage(`{"split_tunnel_enabled":false,"ssl_inspection":true,"log_forwarding":true}`),
		TunnelSettings:      json.RawMessage(`{"device_posture_enabled":true,"posture_check_interval_seconds":120}`),
		InstallSettings:     json.RawMessage(`{"config_sync_interval_mins":10}`),
		TamperproofSettings: json.RawMessage(`{"fail_close_exceptions":{"enabled":true,"process_names":["teamviewer.exe"],"fqdns":["support.example.com"]}}`),
		RoutingSettings: json.RawMessage(`{
			"mode":"split_tunnel",
			"dns":{"resolver":"100.64.0.53","bypass_domains":["teams.microsoft.com","zoom.us"]},
			"traffic":{"bypass_processes":["zoom.exe"],"bypass_domains":["zoom.us"]}
		}`),
	}

	profile := clientConfigToRuntimeProfile(config)

	if !profile.Features.SplitTunnelEnabled {
		t.Fatalf("expected split tunnel to be enabled from routing settings")
	}
	if !profile.Features.DNSRouting {
		t.Fatalf("expected DNS routing to be enabled")
	}
	if profile.DNSRouting.Resolver != "100.64.0.53" {
		t.Fatalf("unexpected resolver: %q", profile.DNSRouting.Resolver)
	}
	if got := len(profile.DNSRouting.Exceptions); got != 2 {
		t.Fatalf("expected 2 DNS bypass domains, got %d", got)
	}
	if profile.Features.SSLInspection {
		t.Fatalf("expected SSL inspection to stay disabled on the client runtime profile")
	}
	if profile.ConfigSyncInterval != 10 {
		t.Fatalf("expected config sync interval of 10 minutes, got %d", profile.ConfigSyncInterval)
	}
	if !profile.FailClose.Enabled || len(profile.FailClose.ProcessNames) != 1 || len(profile.FailClose.FQDNs) != 1 {
		t.Fatalf("expected fail-close exceptions to be preserved, got %#v", profile.FailClose)
	}
}

func TestClientConfigToRoutePoliciesUsesRoutingSettings(t *testing.T) {
	config := db.ClientConfigRecord{
		RoutingSettings: json.RawMessage(`{
			"dns":{"resolver":"100.64.0.53","bypass_domains":["teams.microsoft.com"],"tunnel_exceptions":["admin.teams.microsoft.com"]},
			"traffic":{
				"bypass_processes":["zoom.exe"],
				"bypass_domains":["zoom.us"],
				"bypass_networks":["10.20.0.0/16"],
				"tunnel_process_exceptions":["zoomadmin.exe"],
				"tunnel_domain_exceptions":["secure.zoom.us"],
				"tunnel_network_exceptions":["10.20.10.0/24"]
			}
		}`),
	}

	policies := clientConfigToRoutePolicies(config)
	if len(policies) != 8 {
		t.Fatalf("expected 8 runtime policies, got %d", len(policies))
	}
	if policies[0].PolicyAction != "tunnel" || policies[0].MatchType != "dns_query" {
		t.Fatalf("expected first policy to be DNS tunnel exceptions, got %#v", policies[0])
	}
	last := policies[len(policies)-1]
	if last.PolicyAction != "bypass" || last.MatchType != "domain" || len(last.Patterns) != 1 || last.Patterns[0] != "10.20.0.0/16" {
		t.Fatalf("expected bypass network policy, got %#v", last)
	}
}
