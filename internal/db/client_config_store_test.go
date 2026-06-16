package db

import "testing"

func TestStringSliceScanFromCockroachArrayLiteral(t *testing.T) {
	var value stringSliceScan
	if err := value.Scan(`{"10.0.0.53","100.64.0.1"}`); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(value) != 2 || value[0] != "10.0.0.53" || value[1] != "100.64.0.1" {
		t.Fatalf("unexpected values: %#v", []string(value))
	}
}

func TestStringSliceScanFromJSONLiteral(t *testing.T) {
	var value stringSliceScan
	if err := value.Scan(`["QUIC","TLS"]`); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(value) != 2 || value[0] != "QUIC" || value[1] != "TLS" {
		t.Fatalf("unexpected values: %#v", []string(value))
	}
}

func TestStringSliceScanEmpty(t *testing.T) {
	var value stringSliceScan
	if err := value.Scan(`{}`); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(value) != 0 {
		t.Fatalf("expected empty slice, got %#v", []string(value))
	}
}
