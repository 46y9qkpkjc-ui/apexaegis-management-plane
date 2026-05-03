package db

import (
	"context"
	"database/sql"
	"encoding/json"
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

// NewIdPStore creates a new IdP store.
func NewIdPStore(db *DB, logger *zap.Logger) *IdPStore {
	return &IdPStore{db: db, logger: logger}
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

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_mgmt.identity_providers
			(id, org_id, name, provider_type, enabled, is_default,
			 client_id, client_secret, issuer_url, jwks_uri, token_endpoint, scopes,
			 saml_entity_id, saml_sso_url, saml_certificate,
			 kerberos_enabled, kerberos_realm,
			 scim_enabled, scim_endpoint,
			 attribute_map, group_map, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,now())
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
			attribute_map=EXCLUDED.attribute_map, group_map=EXCLUDED.group_map,
			updated_at=now()`,
		r.ID, r.OrgID, r.Name, r.ProviderType, r.Enabled, r.IsDefault,
		r.ClientID, r.ClientSecret, r.IssuerURL, r.JWKSURI, r.TokenEndpoint, scopes,
		r.SAMLEntityID, r.SAMLSSOURL, r.SAMLCertificate,
		r.KerberosEnabled, r.KerberosRealm,
		r.SCIMEnabled, r.SCIMEndpoint,
		attrJSON, groupJSON,
	)
	return err
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
