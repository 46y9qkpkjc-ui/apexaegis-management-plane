package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/zcp/management-plane/internal/gateway"
)

// GatewayStore implements DB-backed persistence for gateway nodes.
type GatewayStore struct {
	db *DB
}

func NewGatewayStore(db *DB) *GatewayStore {
	return &GatewayStore{db: db}
}

const upsertGateway = `
INSERT INTO system_mgmt.gateway_nodes
    (id, region, name, location, country, provider,
     public_host, quic_endpoint, tls_endpoint, ping_endpoint,
     version, status, deploy_mode, mtls_issued, cert_not_after,
     policy_version, last_heartbeat, registered_at, metadata)
VALUES
    ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
ON CONFLICT (id) DO UPDATE SET
    region         = EXCLUDED.region,
    name           = EXCLUDED.name,
    location       = EXCLUDED.location,
    country        = EXCLUDED.country,
    provider       = EXCLUDED.provider,
    public_host    = EXCLUDED.public_host,
    quic_endpoint  = EXCLUDED.quic_endpoint,
    tls_endpoint   = EXCLUDED.tls_endpoint,
    ping_endpoint  = EXCLUDED.ping_endpoint,
    version        = EXCLUDED.version,
    status         = EXCLUDED.status,
    deploy_mode    = EXCLUDED.deploy_mode,
    mtls_issued    = EXCLUDED.mtls_issued,
    cert_not_after = EXCLUDED.cert_not_after,
    policy_version = EXCLUDED.policy_version,
    last_heartbeat = EXCLUDED.last_heartbeat,
    metadata       = EXCLUDED.metadata
`

// Upsert inserts or updates a gateway node.
func (s *GatewayStore) Upsert(ctx context.Context, gw *gateway.GatewayNode) error {
	meta, err := json.Marshal(gw.Metadata)
	if err != nil {
		meta = []byte("{}")
	}

	_, err = s.db.ExecContext(ctx, upsertGateway,
		gw.ID, gw.Region, gw.Name, gw.Location, gw.Country, gw.Provider,
		gw.PublicHost, gw.QUICEndpoint, gw.TLSEndpoint, gw.PingEndpoint,
		gw.Version, gw.Status, gw.DeployMode, gw.MTLSIssued, gw.CertNotAfter,
		gw.PolicyVersion, gw.LastHeartbeat, gw.RegisteredAt, meta,
	)
	return err
}

// UpdateHeartbeat updates only the heartbeat timestamp and status.
func (s *GatewayStore) UpdateHeartbeat(ctx context.Context, id string, policyVersion int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE system_mgmt.gateway_nodes
		 SET last_heartbeat = $1, status = 'online', policy_version = $2
		 WHERE id = $3`,
		time.Now(), policyVersion, id,
	)
	return err
}

// MarkOffline marks gateways that haven't heartbeated within the threshold as offline.
func (s *GatewayStore) MarkOffline(ctx context.Context, olderThan time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE system_mgmt.gateway_nodes
		 SET status = 'offline'
		 WHERE last_heartbeat < $1 AND status != 'offline'`,
		time.Now().Add(-olderThan),
	)
	return err
}

// DeleteStale removes gateways whose last heartbeat is older than the cutoff
// (a gateway that has been silent this long is treated as decommissioned).
func (s *GatewayStore) DeleteStale(ctx context.Context, olderThan time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM system_mgmt.gateway_nodes WHERE last_heartbeat < $1`,
		time.Now().Add(-olderThan),
	)
	return err
}

// MarkMTLSIssued records mTLS certificate issuance.
func (s *GatewayStore) MarkMTLSIssued(ctx context.Context, id string, notAfter time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE system_mgmt.gateway_nodes
		 SET mtls_issued = TRUE, cert_not_after = $1
		 WHERE id = $2`,
		notAfter, id,
	)
	return err
}

// LoadAll loads all gateway nodes from the database.
func (s *GatewayStore) LoadAll(ctx context.Context) ([]*gateway.GatewayNode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, region, name, location, country, provider,
		        public_host, quic_endpoint, tls_endpoint, ping_endpoint,
		        version, status, deploy_mode, mtls_issued, cert_not_after,
		        policy_version, last_heartbeat, registered_at, metadata
		 FROM system_mgmt.gateway_nodes
		 ORDER BY registered_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var gateways []*gateway.GatewayNode
	for rows.Next() {
		gw := &gateway.GatewayNode{}
		var metaRaw []byte
		var certNotAfter sql.NullTime

		if err := rows.Scan(
			&gw.ID, &gw.Region, &gw.Name, &gw.Location, &gw.Country, &gw.Provider,
			&gw.PublicHost, &gw.QUICEndpoint, &gw.TLSEndpoint, &gw.PingEndpoint,
			&gw.Version, &gw.Status, &gw.DeployMode, &gw.MTLSIssued, &certNotAfter,
			&gw.PolicyVersion, &gw.LastHeartbeat, &gw.RegisteredAt, &metaRaw,
		); err != nil {
			return nil, err
		}

		if certNotAfter.Valid {
			gw.CertNotAfter = &certNotAfter.Time
		}
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &gw.Metadata)
		}

		gateways = append(gateways, gw)
	}
	return gateways, rows.Err()
}
