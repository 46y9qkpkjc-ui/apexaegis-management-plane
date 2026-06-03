package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zcp/management-plane/internal/identity"
	"go.uber.org/zap"
)

// IdPStore provides CRUD for identity provider configurations.
// Implements identity.IdPPersister.
type IdPStore struct {
	db     *DB
	logger *zap.Logger
}

// IdentityAuthProfile maps one IdP connection to a specific product/auth purpose.
type IdentityAuthProfile struct {
	ID               string `json:"id"`
	OrgID            string `json:"org_id"`
	Purpose          string `json:"purpose"`
	DisplayName      string `json:"display_name"`
	Description      string `json:"description"`
	UsePrimaryIdP    bool   `json:"use_primary_idp"`
	IdPID            string `json:"idp_id,omitempty"`
	EffectiveIdPID   string `json:"effective_idp_id,omitempty"`
	EffectiveIdPName string `json:"effective_idp_name,omitempty"`
	Enabled          bool   `json:"enabled"`
	RequireMFA       bool   `json:"require_mfa"`
	AllowJIT         bool   `json:"allow_jit"`
	AllowSCIM        bool   `json:"allow_scim"`
	ContractorAccess bool   `json:"contractor_access"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

var defaultIdentityAuthProfiles = []IdentityAuthProfile{
	{
		Purpose: "admin_console", DisplayName: "Admin console",
		Description:   "Administrator authentication for the management Web UI and ABAC-controlled operations.",
		UsePrimaryIdP: true, Enabled: true, RequireMFA: true,
	},
	{
		Purpose: "desktop_sso", DisplayName: "Desktop client SSO",
		Description:   "User SSO used by desktop, laptop, and mobile clients to pull client and route configuration.",
		UsePrimaryIdP: true, Enabled: true, RequireMFA: true, AllowJIT: true,
	},
	{
		Purpose: "user_portal", DisplayName: "User portal",
		Description:   "Self-service portal authentication for installers, certificates, instructions, and access requests.",
		UsePrimaryIdP: true, Enabled: true, RequireMFA: true, AllowJIT: true, ContractorAccess: true,
	},
	{
		Purpose: "scim_provisioning", DisplayName: "SCIM provisioning",
		Description:   "User and group provisioning source for employees and contractors.",
		UsePrimaryIdP: true, Enabled: true, AllowSCIM: true, ContractorAccess: true,
	},
	{
		Purpose: "access_approval", DisplayName: "Access approval and ITSM",
		Description:   "Identity context for allow/deny approvals, agentic AI workflows, voice approval, and ITSM tickets.",
		UsePrimaryIdP: true, Enabled: true, RequireMFA: true, ContractorAccess: true,
	},
}

// NewIdPStore creates a new IdP store.
func NewIdPStore(db *DB, logger *zap.Logger) *IdPStore {
	return &IdPStore{db: db, logger: logger}
}

// ListAuthProfiles returns the per-purpose IdP usage profiles for an org.
func (s *IdPStore) ListAuthProfiles(ctx context.Context, orgID string) ([]IdentityAuthProfile, error) {
	if err := s.EnsureDefaultAuthProfiles(ctx, orgID); err != nil {
		return nil, err
	}

	primaryID, primaryName, err := s.primaryIdP(ctx, orgID)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id::STRING, p.org_id, p.purpose, p.display_name, p.description,
		       p.use_primary_idp, COALESCE(p.idp_id,''), p.enabled, p.require_mfa,
		       p.allow_jit, p.allow_scim, p.contractor_access,
		       p.created_at::STRING, p.updated_at::STRING,
		       COALESCE(i.name, '')
		FROM system_mgmt.identity_auth_profiles p
		LEFT JOIN system_mgmt.identity_providers i ON i.id = p.idp_id
		WHERE p.org_id = $1
		ORDER BY CASE p.purpose
		  WHEN 'admin_console' THEN 1
		  WHEN 'desktop_sso' THEN 2
		  WHEN 'user_portal' THEN 3
		  WHEN 'scim_provisioning' THEN 4
		  WHEN 'access_approval' THEN 5
		  ELSE 99
		END`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []IdentityAuthProfile
	for rows.Next() {
		var p IdentityAuthProfile
		var explicitName string
		if err := rows.Scan(
			&p.ID, &p.OrgID, &p.Purpose, &p.DisplayName, &p.Description,
			&p.UsePrimaryIdP, &p.IdPID, &p.Enabled, &p.RequireMFA,
			&p.AllowJIT, &p.AllowSCIM, &p.ContractorAccess,
			&p.CreatedAt, &p.UpdatedAt, &explicitName,
		); err != nil {
			return nil, err
		}
		if p.UsePrimaryIdP {
			p.EffectiveIdPID = primaryID
			p.EffectiveIdPName = primaryName
		} else {
			p.EffectiveIdPID = p.IdPID
			p.EffectiveIdPName = explicitName
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// EnsureDefaultAuthProfiles creates the five purpose profiles for an org.
func (s *IdPStore) EnsureDefaultAuthProfiles(ctx context.Context, orgID string) error {
	if strings.TrimSpace(orgID) == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	for _, p := range defaultIdentityAuthProfiles {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO system_mgmt.identity_auth_profiles
			  (org_id, purpose, display_name, description, use_primary_idp, enabled, require_mfa, allow_jit, allow_scim, contractor_access)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (org_id, purpose) DO NOTHING`,
			orgID, p.Purpose, p.DisplayName, p.Description, p.UsePrimaryIdP, p.Enabled, p.RequireMFA, p.AllowJIT, p.AllowSCIM, p.ContractorAccess,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpsertAuthProfiles updates one or more purpose profiles.
func (s *IdPStore) UpsertAuthProfiles(ctx context.Context, orgID string, profiles []IdentityAuthProfile) error {
	if strings.TrimSpace(orgID) == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	for _, p := range profiles {
		if p.Purpose == "" {
			return fmt.Errorf("auth profile purpose is required")
		}
		if !p.UsePrimaryIdP && strings.TrimSpace(p.IdPID) == "" {
			return fmt.Errorf("auth profile %s requires idp_id when use_primary_idp is false", p.Purpose)
		}
		defaults := defaultAuthProfileForPurpose(p.Purpose)
		if p.DisplayName == "" {
			p.DisplayName = defaults.DisplayName
		}
		if p.Description == "" {
			p.Description = defaults.Description
		}
		idpID := sql.NullString{String: strings.TrimSpace(p.IdPID), Valid: strings.TrimSpace(p.IdPID) != ""}
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO system_mgmt.identity_auth_profiles
			  (org_id, purpose, display_name, description, use_primary_idp, idp_id, enabled, require_mfa, allow_jit, allow_scim, contractor_access, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
			ON CONFLICT (org_id, purpose) DO UPDATE SET
			  display_name=EXCLUDED.display_name,
			  description=EXCLUDED.description,
			  use_primary_idp=EXCLUDED.use_primary_idp,
			  idp_id=EXCLUDED.idp_id,
			  enabled=EXCLUDED.enabled,
			  require_mfa=EXCLUDED.require_mfa,
			  allow_jit=EXCLUDED.allow_jit,
			  allow_scim=EXCLUDED.allow_scim,
			  contractor_access=EXCLUDED.contractor_access,
			  updated_at=now()`,
			orgID, p.Purpose, p.DisplayName, p.Description, p.UsePrimaryIdP, idpID, p.Enabled, p.RequireMFA, p.AllowJIT, p.AllowSCIM, p.ContractorAccess,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func defaultAuthProfileForPurpose(purpose string) IdentityAuthProfile {
	for _, p := range defaultIdentityAuthProfiles {
		if p.Purpose == purpose {
			return p
		}
	}
	return IdentityAuthProfile{Purpose: purpose, DisplayName: purpose, UsePrimaryIdP: true, Enabled: true, RequireMFA: true}
}

func (s *IdPStore) primaryIdP(ctx context.Context, orgID string) (string, string, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name
		FROM system_mgmt.identity_providers
		WHERE org_id = $1 AND enabled = true
		ORDER BY is_default DESC, name ASC
		LIMIT 1`, orgID)
	var id, name string
	if err := row.Scan(&id, &name); err != nil {
		if err == sql.ErrNoRows {
			return "", "", nil
		}
		return "", "", err
	}
	return id, name, nil
}

// List returns all identity providers.
func (s *IdPStore) List(ctx context.Context) ([]identity.IdPDBRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, name, provider_type, enabled, is_default,
		       COALESCE(client_id,''), COALESCE(client_secret,''),
		       COALESCE(issuer_url,''), COALESCE(jwks_uri,''),
		       COALESCE(token_endpoint,''), COALESCE(scopes,''),
		       COALESCE(saml_entity_id,''), COALESCE(saml_sso_url,''),
		       COALESCE(saml_certificate,''),
		       kerberos_enabled, COALESCE(kerberos_realm,''),
		       scim_enabled, COALESCE(scim_endpoint,''),
		       COALESCE(attribute_map,'{}'), COALESCE(group_map,'{}')
		FROM system_mgmt.identity_providers
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []identity.IdPDBRecord
	for rows.Next() {
		r, err := scanIdP(rows)
		if err != nil {
			s.logger.Error("scan idp row", zap.Error(err))
			continue
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// Get returns a single identity provider by ID.
func (s *IdPStore) Get(ctx context.Context, id string) (*identity.IdPDBRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, name, provider_type, enabled, is_default,
		       COALESCE(client_id,''), COALESCE(client_secret,''),
		       COALESCE(issuer_url,''), COALESCE(jwks_uri,''),
		       COALESCE(token_endpoint,''), COALESCE(scopes,''),
		       COALESCE(saml_entity_id,''), COALESCE(saml_sso_url,''),
		       COALESCE(saml_certificate,''),
		       kerberos_enabled, COALESCE(kerberos_realm,''),
		       scim_enabled, COALESCE(scim_endpoint,''),
		       COALESCE(attribute_map,'{}'), COALESCE(group_map,'{}')
		FROM system_mgmt.identity_providers WHERE id = $1`, id)
	return scanIdPRow(row)
}

// Upsert inserts or updates an identity provider.
func (s *IdPStore) Upsert(ctx context.Context, r *identity.IdPDBRecord) error {
	attrJSON, _ := json.Marshal(r.AttributeMap)
	groupJSON, _ := json.Marshal(r.GroupMap)
	scopes := strings.Join(r.Scopes, ",")
	scimTokenHash := ""
	if strings.TrimSpace(r.SCIMToken) != "" {
		scimTokenHash = hashIdPSCIMToken(r.SCIMToken)
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.identity_providers
			(id, org_id, name, provider_type, enabled, is_default,
			 client_id, client_secret, issuer_url, jwks_uri, token_endpoint, scopes,
			 saml_entity_id, saml_sso_url, saml_certificate,
			 kerberos_enabled, kerberos_realm,
			 scim_enabled, scim_endpoint, scim_token_hash,
			 attribute_map, group_map, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NULLIF($20,''),$21,$22,now())
		ON CONFLICT (id) DO UPDATE SET
			org_id=EXCLUDED.org_id, name=EXCLUDED.name, provider_type=EXCLUDED.provider_type,
			enabled=EXCLUDED.enabled, is_default=EXCLUDED.is_default,
			client_id=EXCLUDED.client_id, client_secret=EXCLUDED.client_secret,
			issuer_url=EXCLUDED.issuer_url, jwks_uri=EXCLUDED.jwks_uri,
			token_endpoint=EXCLUDED.token_endpoint, scopes=EXCLUDED.scopes,
			saml_entity_id=EXCLUDED.saml_entity_id, saml_sso_url=EXCLUDED.saml_sso_url,
			saml_certificate=EXCLUDED.saml_certificate,
			kerberos_enabled=EXCLUDED.kerberos_enabled, kerberos_realm=EXCLUDED.kerberos_realm,
			scim_enabled=EXCLUDED.scim_enabled, scim_endpoint=EXCLUDED.scim_endpoint,
			scim_token_hash=COALESCE(EXCLUDED.scim_token_hash, system_mgmt.identity_providers.scim_token_hash),
			attribute_map=EXCLUDED.attribute_map, group_map=EXCLUDED.group_map,
			updated_at=now()`,
		r.ID, r.OrgID, r.Name, r.ProviderType, r.Enabled, r.IsDefault,
		r.ClientID, r.ClientSecret, r.IssuerURL, r.JWKSURI, r.TokenEndpoint, scopes,
		r.SAMLEntityID, r.SAMLSSOURL, r.SAMLCertificate,
		r.KerberosEnabled, r.KerberosRealm,
		r.SCIMEnabled, r.SCIMEndpoint,
		scimTokenHash,
		attrJSON, groupJSON,
	)
	return err
}

func hashIdPSCIMToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Delete removes an identity provider by ID.
func (s *IdPStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM system_mgmt.identity_providers WHERE id = $1`, id)
	return err
}

// ── scan helpers ────────────────────────────────────────────────

type scannable interface {
	Scan(dest ...any) error
}

func scanIdP(s scannable) (identity.IdPDBRecord, error) {
	var r identity.IdPDBRecord
	var scopesStr, attrJSON, groupJSON string
	err := s.Scan(
		&r.ID, &r.OrgID, &r.Name, &r.ProviderType, &r.Enabled, &r.IsDefault,
		&r.ClientID, &r.ClientSecret,
		&r.IssuerURL, &r.JWKSURI, &r.TokenEndpoint, &scopesStr,
		&r.SAMLEntityID, &r.SAMLSSOURL, &r.SAMLCertificate,
		&r.KerberosEnabled, &r.KerberosRealm,
		&r.SCIMEnabled, &r.SCIMEndpoint,
		&attrJSON, &groupJSON,
	)
	if err != nil {
		return r, err
	}
	if scopesStr != "" {
		r.Scopes = strings.Split(scopesStr, ",")
	}
	if attrJSON != "" && attrJSON != "{}" {
		json.Unmarshal([]byte(attrJSON), &r.AttributeMap)
	}
	if groupJSON != "" && groupJSON != "{}" {
		json.Unmarshal([]byte(groupJSON), &r.GroupMap)
	}
	return r, nil
}

func scanIdPRow(row *sql.Row) (*identity.IdPDBRecord, error) {
	var r identity.IdPDBRecord
	var scopesStr, attrJSON, groupJSON string
	err := row.Scan(
		&r.ID, &r.OrgID, &r.Name, &r.ProviderType, &r.Enabled, &r.IsDefault,
		&r.ClientID, &r.ClientSecret,
		&r.IssuerURL, &r.JWKSURI, &r.TokenEndpoint, &scopesStr,
		&r.SAMLEntityID, &r.SAMLSSOURL, &r.SAMLCertificate,
		&r.KerberosEnabled, &r.KerberosRealm,
		&r.SCIMEnabled, &r.SCIMEndpoint,
		&attrJSON, &groupJSON,
	)
	if err != nil {
		return nil, err
	}
	if scopesStr != "" {
		r.Scopes = strings.Split(scopesStr, ",")
	}
	if attrJSON != "" && attrJSON != "{}" {
		json.Unmarshal([]byte(attrJSON), &r.AttributeMap)
	}
	if groupJSON != "" && groupJSON != "{}" {
		json.Unmarshal([]byte(groupJSON), &r.GroupMap)
	}
	return &r, nil
}
