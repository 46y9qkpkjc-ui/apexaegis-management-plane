package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
)

// The MSP demo hinges on callerScope translating a login into the right tenant
// visibility, and TenantScope.Allows gating per-tenant drill-ins. This locks the
// isolation contract: April (StarHub operator) sees her fleet, Samuel (Aspire
// admin) sees only Aspire, and neither can reach a rival's tenant.
func TestCallerScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := func(role, operatorScope, orgID string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("role", role)
		if operatorScope != "" {
			c.Set("operator_scope", operatorScope)
		}
		if orgID != "" {
			c.Set("user_org_id", orgID)
		}
		return c
	}

	cases := []struct {
		name string
		c    *gin.Context
		want db.TenantScope
	}{
		{"super_admin unrestricted", ctx("super_admin", "", "a0000000-0000-0000-0000-000000000001"), db.TenantScope{}},
		{"april MSP → StarHub fleet", ctx("org_admin", "StarHub", "d5000000-0000-0000-0000-000000000001"), db.TenantScope{Operator: "StarHub"}},
		{"samuel tenant admin → own org", ctx("org_admin", "", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), db.TenantScope{OrgID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}},
	}
	for _, tc := range cases {
		if got := callerScope(tc.c); got != tc.want {
			t.Errorf("%s: callerScope = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestTenantScopeAllows(t *testing.T) {
	const (
		aspire = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		google = "10000000-0000-0000-0000-000000000000"
	)
	cases := []struct {
		name          string
		scope         db.TenantScope
		operator, org string
		want          bool
	}{
		{"platform sees anything", db.TenantScope{}, "ApexAegis (direct)", google, true},
		{"april into StarHub tenant (Aspire)", db.TenantScope{Operator: "StarHub"}, "StarHub", aspire, true},
		{"april blocked from a non-StarHub tenant", db.TenantScope{Operator: "StarHub"}, "Singtel", google, false},
		{"samuel into own org (Aspire)", db.TenantScope{OrgID: aspire}, "StarHub", aspire, true},
		{"samuel blocked from another org", db.TenantScope{OrgID: aspire}, "StarHub", "d5000000-0000-0000-0000-000000000002", false},
	}
	for _, tc := range cases {
		if got := tc.scope.Allows(tc.operator, tc.org); got != tc.want {
			t.Errorf("%s: Allows(%q,%q) = %v, want %v", tc.name, tc.operator, tc.org, got, tc.want)
		}
	}
}
