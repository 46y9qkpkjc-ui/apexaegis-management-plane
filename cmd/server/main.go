package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/soheilhy/cmux"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/zcp/management-plane/internal/api/handlers"
	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/assistant"
	"github.com/zcp/management-plane/internal/audit"
	"github.com/zcp/management-plane/internal/auth"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/dot1x"
	"github.com/zcp/management-plane/internal/enforcement"
	"github.com/zcp/management-plane/internal/gateway"
	"github.com/zcp/management-plane/internal/grant"
	"github.com/zcp/management-plane/internal/grpc/dnssec"
	"github.com/zcp/management-plane/internal/grpcserver"
	"github.com/zcp/management-plane/internal/identity"
	"github.com/zcp/management-plane/internal/policy"
	"github.com/zcp/management-plane/internal/posture"
	"github.com/zcp/management-plane/internal/radsec"
	"github.com/zcp/management-plane/internal/risk"
	"github.com/zcp/management-plane/internal/scanner"
	"github.com/zcp/management-plane/internal/sdn"
	"github.com/zcp/management-plane/internal/security"
	"github.com/zcp/management-plane/internal/segment"
	"github.com/zcp/management-plane/internal/threat-intel"
	"github.com/zcp/management-plane/internal/threatfeed"
	"github.com/zcp/management-plane/internal/validation"
	"github.com/zcp/management-plane/internal/websocket"
)

func main() {
	logger, _ := newLogger()
	defer logger.Sync()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Internal CA for mTLS with gateways ──
	caKeyFile := envOrDefault("CA_KEY_FILE", "/etc/apexaegis/ca/ca-key.pem")
	caCertFile := envOrDefault("CA_CERT_FILE", "/etc/apexaegis/ca/ca-cert.pem")

	ca, err := auth.LoadOrCreateCA(caCertFile, caKeyFile)
	if err != nil {
		logger.Fatal("Failed to initialize CA", zap.Error(err))
	}
	logger.Info("Internal CA loaded",
		zap.String("subject", ca.Certificate.Subject.CommonName),
		zap.Time("not_after", ca.Certificate.NotAfter),
	)

	// ── Gateway registry ──
	gwRegistry := gateway.NewRegistry(ca, logger)

	// Seed gateway API keys from environment variables.
	// Format: GATEWAY_API_KEYS=key1:gatewayID1,key2:gatewayID2
	// Also supports a single key via GATEWAY_API_KEY=key:gatewayID or just GATEWAY_API_KEY=key (any gateway)
	if apiKeysEnv := os.Getenv("GATEWAY_API_KEYS"); apiKeysEnv != "" {
		for _, entry := range strings.Split(apiKeysEnv, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
			if len(parts) == 2 {
				gwRegistry.RegisterAPIKey(parts[0], parts[1])
				logger.Info("Registered gateway API key", zap.String("gateway_id", parts[1]))
			}
		}
	}
	// Single key shortcut: GATEWAY_API_KEY=<key> (registers for both known gateways)
	if singleKey := os.Getenv("GATEWAY_API_KEY"); singleKey != "" {
		gwRegistry.RegisterAPIKey(singleKey, "ap-southeast-1")
		gwRegistry.RegisterAPIKey(singleKey, "ap-southeast-2")
		logger.Info("Registered shared gateway API key for ap-southeast-1 and ap-southeast-2")
	}

	// ── CockroachDB Cloud ──
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Fatal("DATABASE_URL is required — set it to your CockroachDB Cloud connection string")
	}

	tenantOrgID := envOrDefault("APP_TENANT_ORG_ID", db.SystemThreatOrgID)
	dbConn, err := db.Open(db.Config{DSN: databaseURL, TenantOrgID: tenantOrgID}, logger)
	if err != nil {
		logger.Fatal("Failed to connect to CockroachDB Cloud", zap.Error(err))
	}

	// Run schema migrations on startup (idempotent — skips already-applied)
	migrationsDir := envOrDefault("MIGRATIONS_DIR", "internal/db/migrations")
	if migErr := dbConn.Migrate(migrationsDir); migErr != nil {
		logger.Fatal("Schema migration failed",
			zap.Error(migErr),
			zap.String("migration_dir", migrationsDir),
		)
	}

	// ── Stores (CockroachDB Cloud backed) ──
	policyStore := db.NewPolicyStore(dbConn, logger)
	policyStore.LoadDefaults()

	featureStore := db.NewFeatureStore(dbConn)
	profileStore := db.NewProfileStore(dbConn)
	deviceStore := db.NewDeviceStore(dbConn, logger)
	urlCategoryStore := db.NewURLCategoryStore(dbConn, logger)

	// EDR/MDM posture connectors — consume an existing EDR's device-health verdict
	// into the posture pipeline (we complement EDR, we don't ship a sensor). Off
	// unless credentials are set; the runner no-ops with no enabled connectors.
	startPostureConnectors(ctx, deviceStore, db.NewTenantStore(dbConn, logger), logger)
	policyObjectStore := db.NewPolicyObjectStore(dbConn, logger)
	clientConfigStore := db.NewClientConfigStore(dbConn, logger)

	// ── Device-grant issuer (machine-tunnel DC-scope grants) ──
	// Mints the private-access grant the gateway verifies; uses the SAME shared
	// signing key the gateways verify with. Optional — disabled if the key is unset.
	var deviceGrantHandler *handlers.DeviceGrantHandler
	if grantKey := os.Getenv("PRIVATE_ACCESS_GRANT_SIGNING_KEY"); grantKey != "" {
		// 20-min TTL (not the 5-min default): grants are cross-cloud (AWS MP →
		// Azure ad-gw) and a short TTL is fragile against clock skew. Still short
		// enough to bound a leaked bearer grant.
		grantIssuer, gErr := grant.NewIssuer(grantKey,
			grant.WithIssuer(envOrDefault("DEVICE_API_DOMAIN", grant.DefaultIssuer)),
			grant.WithTTL(20*time.Minute))
		if gErr != nil {
			logger.Warn("device-grant issuance disabled: invalid PRIVATE_ACCESS_GRANT_SIGNING_KEY", zap.Error(gErr))
		} else if dcSegments, sErr := handlers.NewConfigDCSegments(os.Getenv("DEVICE_GRANT_DC_SEGMENTS")); sErr != nil {
			logger.Warn("device-grant issuance disabled: invalid DEVICE_GRANT_DC_SEGMENTS", zap.Error(sErr))
		} else {
			deviceGrantHandler = handlers.NewDeviceGrantHandler(deviceStore, grantIssuer, dcSegments, logger)
			logger.Info("device-grant issuance enabled (machine-tunnel DC-scope grants)")
		}
	} else {
		logger.Info("device-grant issuance disabled (set PRIVATE_ACCESS_GRANT_SIGNING_KEY to enable)")
	}

	// ── Gateway registry persistence ──
	gwStore := db.NewGatewayStore(dbConn)
	gwRegistry.SetStore(gwStore)
	if err := gwRegistry.LoadFromDB(ctx); err != nil {
		logger.Warn("Failed to restore gateway registry from DB (starting fresh)", zap.Error(err))
	}
	go gwRegistry.StartCleanupLoop(ctx)
	// Classify private-access ingress brokers (QUIC micro-tunnel) so they are
	// excluded from the selectable SWG PoP list and surfaced on /private-gateways.
	// A broker may also self-declare via registration metadata kind=private-access.
	gwRegistry.SetPrivateAccessIDs(strings.Split(envOrDefault("PRIVATE_ACCESS_GATEWAY_IDS", "ad-gw.apexaegis.app"), ","))

	// ── Auth store (user authentication + JWT) ──
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		logger.Fatal("JWT_SECRET is required — set a strong random secret (32+ chars)")
	}
	authStore := db.NewAuthStore(dbConn, []byte(jwtSecret), logger)

	// Device-cert issuer: prefer the device step-ca; fall back to legacy ACM PCA.
	var deviceCA security.DeviceCertificateIssuer
	var enrolCA *security.StepCADeviceCA // concrete step-ca — mints MP-brokered enrol tokens
	if stepca, scErr := security.NewStepCADeviceCA(ctx); scErr == nil {
		deviceCA = stepca
		enrolCA = stepca
		logger.Info("device enrollment: device step-ca enabled")
	} else if pca, pcaErr := security.NewAWSPrivateCA(ctx); pcaErr == nil {
		deviceCA = pca
		logger.Info("device enrollment: AWS Private CA (legacy) enabled")
	} else {
		logger.Warn("device enrollment disabled",
			zap.NamedError("stepca", scErr), zap.NamedError("acmpca", pcaErr))
	}

	// Kerberos SSO validator: OFFLINE SPNEGO validation via a service keytab.
	// Keytab is delivered base64 in MP_KRB5_KEYTAB_B64 (SSM SecureString); SPN
	// and realm are non-secret plain env (MP_KRB5_SPN / MP_KRB5_REALM). Nil when
	// unset → /agent/sso/kerberos returns 503. Never contacts the DC — the client
	// acquires its ticket over the gateway machine-tunnel, the MP only decrypts it.
	var kerberosValidator *security.KerberosValidator
	if ktB64 := os.Getenv("MP_KRB5_KEYTAB_B64"); ktB64 != "" {
		if kv, kvErr := security.NewKerberosValidator(ktB64, os.Getenv("MP_KRB5_SPN"), os.Getenv("MP_KRB5_REALM"), logger); kvErr != nil {
			logger.Warn("kerberos sso disabled: invalid keytab config", zap.Error(kvErr))
		} else {
			kerberosValidator = kv
			logger.Info("kerberos sso enabled", zap.String("spn", kv.SPN()), zap.String("realm", kv.Realm()))
		}
	}

	// ── SCIM store (admin + client user provisioning) ──
	scimStore := db.NewSCIMStore(dbConn, logger)
	provStore := db.NewProvisioningStore(dbConn, db.NewDirectoryStore(dbConn, logger), logger)

	// ── P2P mesh coordinator ──
	meshCoordinator := gateway.NewMeshCoordinator(logger)

	// ── WebSocket policy push hub ──
	wsHub := websocket.NewHub(policyStore, logger)
	go wsHub.Run(ctx)

	// ── Audit log system ──
	auditLog := audit.NewAuditLog(logger)

	// ── TLS compliance scanner + ApexAdversary outreach ──
	tlsScanner := scanner.NewScanner(logger)
	outreachEngine := scanner.NewOutreachEngine(scanner.OutreachConfig{
		ApexAdversaryAPI: envOrDefault("APEX_ADVERSARY_API", "https://apexadversary.com/api/v1"),
		APIKey:           os.Getenv("APEX_ADVERSARY_API_KEY"),
		SMTPEndpoint:     envOrDefault("SMTP_ENDPOINT", "https://api.apexaegis.io/smtp/v1/send"),
		FromEmail:        envOrDefault("OUTREACH_FROM_EMAIL", "security@apexaegis.io"),
	}, logger)

	// ── Dot1X HTTPS-based authenticator (replaces RADIUS) ──
	dot1xAuth := dot1x.NewAuthenticator(nil, logger)

	// ── Cloud RADIUS: native RadSec (RADIUS-over-TLS, TCP 2083) + EAP-TLS ──
	// Terminates the RADIUS/EAP-TLS protocol from an on-prem radsecproxy and
	// delegates the access decision to the dot1x PDP above. Disabled unless the
	// RadSec/EAP cert material is configured (RADSEC_*_FILE env).
	// sessionEnforcer is the network-plane kill switch (RFC 5176 CoA/Disconnect
	// over RadSec). nil unless RadSec is configured; the dot1x handler falls back
	// to an in-memory flip when it's nil.
	var sessionEnforcer handlers.SessionEnforcer
	if rscfg, ok := radsec.ConfigFromEnv(); ok {
		if rs, err := radsec.NewServer(rscfg, &radsecPDP{auth: dot1xAuth}, logger); err != nil {
			logger.Error("radsec: disabled — cert load failed", zap.Error(err))
		} else {
			go rs.Run(ctx)
			sessionEnforcer = radsecEnforcer{rs: rs}
			logger.Info("radsec: Cloud RADIUS enabled", zap.String("addr", rscfg.ListenAddr))
		}
	} else {
		logger.Info("radsec: Cloud RADIUS disabled (set RADSEC_*_FILE env to enable)")
	}

	// Continuous enforcement PDP: turns a posture DROP into a CoA/Disconnect at the
	// NAS (POSTURE_COA_ACTION=off|quarantine|disconnect, default off), and on a hard
	// disconnect also blocks the device's cert renewal (the dead-man's timer).
	enforcementCtl := enforcement.ConfigFromEnv(sessionEnforcer, logger).WithRenewalBlocker(deviceStore)
	if enforcementCtl.Enabled() {
		logger.Info("enforcement: posture-drop auto-CoA enabled")
	}

	// ── Advanced Security Group Tags (SGT) with multi-domain context ──
	sgtStore := segment.NewStore(logger)

	// ── Identity Broker (IdP federation + attribute normalization) ──
	idBroker := identity.NewBroker(logger)
	idpStore := db.NewIdPStore(dbConn, logger)
	idBroker.SetPersister(idpStore)

	// ── IdP Configuration Logging (audit trail for IdP changes) ──
	idpLogStore := db.NewIdPLogStore(dbConn, logger)

	// ── SDN whitebox switch manager ──
	sdnManager := sdn.NewManager(logger)

	// ── Feature licensing ──
	orgPlan := envOrDefault("ORG_PLAN", "enterprise")

	// ── Security Validation engine (container-based test infrastructure) ──
	validationEngine := validation.NewEngine(logger)

	// ── Key Vault: AES-256-GCM envelope encryption for all key material ──
	vaultPassphrase := envOrDefault("VAULT_PASSPHRASE", "")
	if vaultPassphrase == "" {
		logger.Fatal("VAULT_PASSPHRASE is required — set an env var or mount from HSM/Vault")
	}
	vaultStorePath := envOrDefault("VAULT_STORE_PATH", "/etc/apexaegis/vault")
	keyVault, err := security.NewKeyVault(security.VaultConfig{
		Passphrase: vaultPassphrase,
		StorePath:  vaultStorePath,
	}, logger)
	if err != nil {
		logger.Fatal("Failed to initialize key vault", zap.Error(err))
	}
	logger.Info("Key vault initialized", zap.String("store", vaultStorePath))

	// Seal CA root private key in vault (envelope-encrypted at rest)
	caVaultID := "ca-root-key"
	if !keyVault.Has(caVaultID) {
		caKeyDER, marshalErr := x509.MarshalECPrivateKey(ca.PrivateKey)
		if marshalErr != nil {
			logger.Fatal("Failed to marshal CA key for vault", zap.Error(marshalErr))
		}
		if sealErr := keyVault.Seal(caVaultID, "CA Root ECDSA P-384 Key", "ecdsa-P-384", caKeyDER); sealErr != nil {
			logger.Fatal("Failed to seal CA key in vault", zap.Error(sealErr))
		}
		logger.Info("CA root key sealed in vault")
	}

	// ── Code signing, enrollment tokens, command signing ──
	codeSigningSvc := security.NewCodeSigningService(logger)
	enrollmentSvc := security.NewEnrollmentService(logger, ca)
	commandSigningSvc := security.NewCommandSigningService(codeSigningSvc, logger)

	// ── JWKS key rotation (manages Ed25519 signing keys + ECDSA CA keys) ──
	jwksSvc := security.NewJWKSService(keyVault, codeSigningSvc, security.JWKSConfig{
		RotationInterval: 90 * 24 * time.Hour, // rotate every 90 days
		OverlapDuration:  7 * 24 * time.Hour,  // old key valid 7 days after rotation
	}, logger)

	// Import existing signing key and CA key into JWKS for rotation management
	codeSigningSvc.ImportActiveKeyIntoJWKS(jwksSvc)
	if importErr := jwksSvc.ImportExistingECDSAKey("ca-root", ca.PrivateKey); importErr != nil {
		logger.Error("Failed to import CA key into JWKS", zap.Error(importErr))
	}

	// Start JWKS rotation loop (checks every 24 hours)
	jwksStop := make(chan struct{})
	go jwksSvc.RotationLoop(jwksStop, 24*time.Hour)

	// ── HTTP API (Gin) ──
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(middleware.RequestID())
	router.Use(middleware.SafeRecovery())
	router.Use(middleware.ErrorHandler())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.CORS())

	// Public health endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "timestamp": time.Now().UTC()})
	})

	// JWKS endpoint — public (gateways/agents fetch this to verify signatures)
	router.GET("/.well-known/jwks.json", func(c *gin.Context) {
		jwksJSON, jwksErr := jwksSvc.MarshalJWKS()
		if jwksErr != nil {
			c.JSON(500, gin.H{"error": "failed to serialize JWKS"})
			return
		}
		c.Header("Cache-Control", "public, max-age=3600")
		c.Data(200, "application/json", jwksJSON)
	})

	// Authentication API (public — no JWT required)
	authAPI := router.Group("/api/v1/auth")
	{
		authHandler := handlers.NewAuthHandler(authStore, logger)
		authAPI.POST("/login", authHandler.Login)
		authAPI.POST("/refresh", authHandler.Refresh)
		authAPI.POST("/logout", authHandler.Logout)
		authAPI.GET("/me", middleware.JWTAuth(authStore), authHandler.Me)

		// SSO/OIDC login flow (Okta, Azure AD, etc.)
		ssoHandler := handlers.NewSSOHandler(idBroker, authStore, scimStore, logger)
		authAPI.GET("/sso/providers", ssoHandler.ListSSOProviders)
		authAPI.GET("/sso/:idp_id/authorize", ssoHandler.Authorize)
		authAPI.GET("/sso/callback", ssoHandler.CallbackRedirect)
		authAPI.POST("/sso/callback", ssoHandler.Callback)

		// Browser Kerberos SSO (SPNEGO/Negotiate) — silent sign-in for a
		// domain-joined browser (e.g. April in her AD.APEXAEGIS.APP WorkSpace).
		// Reuses the same offline keytab validator as the agent path; a nil
		// validator (keytab not configured) makes /negotiate return 503.
		negotiateHandler := handlers.NewNegotiateHandler(kerberosValidator, authStore, os.Getenv("MP_KRB5_UPN_SUFFIX"), logger)
		authAPI.GET("/negotiate", negotiateHandler.Negotiate)
		authAPI.POST("/negotiate/exchange", negotiateHandler.Exchange)
	}

	// Client self-serve onboarding OTP API (public — no JWT; gated by emailed OTP).
	onboardAPI := router.Group("/api/v1/onboard")
	{
		onboardHandler := handlers.NewOnboardHandler(dbConn, logger)
		onboardAPI.POST("/otp/request", onboardHandler.RequestOTP)
		onboardAPI.POST("/otp/verify", onboardHandler.VerifyOTP)
	}

	// Self-service user portal API (SCIM client-user JWT only).
	portalAPI := router.Group("/api/v1/portal")
	portalAPI.Use(middleware.JWTAuth(authStore))
	portalAPI.Use(middleware.RequireRole("client_user"))
	{
		// enrolCA (the concrete step-ca client) also mints BYOD tokens; it's nil when
		// the device step-ca isn't configured, and the handler 503s in that case.
		var byodMinter security.EnrolTokenMinter
		if enrolCA != nil {
			byodMinter = enrolCA
		}
		portalHandler := handlers.NewPortalHandler(scimStore, deviceStore, deviceCA, byodMinter, logger)
		portalAPI.GET("/profile", portalHandler.Profile)
		portalAPI.GET("/artifacts", portalHandler.Artifacts)
		portalAPI.POST("/devices/certificates", portalHandler.IssueDeviceCertificate)
		// BYOD onboarding: user-scoped step-ca token, identity from the SSO session.
		portalAPI.POST("/byod/token", portalHandler.IssueBYODToken)
	}

	// AD-sync connector API (outbound-only; Infra-CA mTLS enforced in the handler
	// via the dedicated connector listener — no JWT).
	connectorAPI := router.Group("/api/v1/connector")
	{
		connectorStore := db.NewConnectorStore(dbConn, logger)
		connectorHandler := handlers.NewConnectorHandler(connectorStore, provStore, logger)
		connectorAPI.GET("/config", connectorHandler.GetConfig)
		connectorAPI.POST("/sync", connectorHandler.PostSync)
	}

	// User Management API (admin-only)
	userAPI := router.Group("/api/v1/users")
	userAPI.Use(middleware.JWTAuth(authStore))
	userAPI.Use(middleware.RequireWriteAccess())
	{
		userHandler := handlers.NewUserHandler(authStore, logger)
		userAPI.GET("", userHandler.ListUsers)
		userAPI.GET("/:id", userHandler.GetUser)
		userAPI.PUT("/:id", userHandler.UpdateUser)
		userAPI.DELETE("/:id", userHandler.DeleteUser)
	}

	// Client Users API (admin-only — manage endpoint users from web UI)
	clientAPI := router.Group("/api/v1/client-users")
	clientAPI.Use(middleware.JWTAuth(authStore))
	clientAPI.Use(middleware.RequireWriteAccess())
	{
		clientAPI.GET("", func(c *gin.Context) {
			filter := c.Query("search")
			users, _, err := scimStore.ListClientUsers(c.Request.Context(), c.GetString("org_id"), filter, 1, 200)
			if err != nil {
				c.JSON(500, gin.H{"error": "failed to list client users"})
				return
			}
			if users == nil {
				users = []db.SCIMUser{}
			}
			c.JSON(200, users)
		})
		clientAPI.GET("/:id/status-events", func(c *gin.Context) {
			events, err := scimStore.ListClientUserStatusEvents(c.Request.Context(), c.GetString("org_id"), c.Param("id"), 25)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list client user status events"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"events": events})
		})
		clientAPI.POST("/:id/reactivate", func(c *gin.Context) {
			var req struct {
				Reason string `json:"reason"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}
			user, err := scimStore.ReactivateClientUser(c.Request.Context(), c.GetString("org_id"), c.Param("id"), c.GetString("user_id"), strings.TrimSpace(req.Reason))
			if err != nil {
				status := http.StatusBadRequest
				if strings.Contains(err.Error(), "IdP policy") || strings.Contains(err.Error(), "Okta") {
					status = http.StatusConflict
				}
				c.JSON(status, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, user)
		})
	}

	// Device Inventory API (admin-only — mTLS registered endpoint devices)
	deviceAPI := router.Group("/api/v1/devices")
	deviceAPI.Use(middleware.JWTAuth(authStore))
	deviceAPI.Use(middleware.RequireWriteAccess())
	{
		deviceHandler := handlers.NewDeviceHandler(deviceStore, logger)
		deviceAPI.GET("", deviceHandler.ListDevices)
		deviceAPI.GET("/:id", deviceHandler.GetDevice)
	}

	// Objects API (admin-only) — URL categories and their domain membership.
	objectsAPI := router.Group("/api/v1/objects")
	objectsAPI.Use(middleware.JWTAuth(authStore))
	objectsAPI.Use(middleware.RequireWriteAccess())
	{
		urlCatHandler := handlers.NewURLCategoryHandler(urlCategoryStore, logger)
		objectsAPI.GET("/url-categories", urlCatHandler.ListCategories)
		objectsAPI.GET("/url-categories/:id", urlCatHandler.GetCategory)
		objectsAPI.GET("/categorize", urlCatHandler.Categorize)

		objHandler := handlers.NewPolicyObjectHandler(policyObjectStore, logger)
		objectsAPI.GET("/cloud-apps", objHandler.ListCloudApps)
		objectsAPI.GET("/device-groups", objHandler.ListDeviceGroups)
	}

	// Group Inventory API (admin-only — includes SCIM-pushed groups)
	groupAPI := router.Group("/api/v1/groups")
	groupAPI.Use(middleware.JWTAuth(authStore))
	groupAPI.Use(middleware.RequireWriteAccess())
	{
		groupHandler := handlers.NewGroupHandler(scimStore, logger)
		groupAPI.GET("", groupHandler.ListGroups)
		groupAPI.POST("", groupHandler.CreateGroup)
		groupAPI.PUT("/:id", groupHandler.UpdateGroup)
		groupAPI.DELETE("/:id", groupHandler.DeleteGroup)
		// Directory-import toggle: enable/disable provisioning from an AD (ldap) group,
		// then reconcile immediately so onboarding/offboarding reflects the change.
		groupAPI.PUT("/:id/import", func(c *gin.Context) {
			var req struct {
				ImportEnabled bool `json:"import_enabled"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
				return
			}
			if err := scimStore.SetGroupImportEnabled(c.Request.Context(), db.SystemThreatOrgID, c.Param("id"), req.ImportEnabled); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			res, err := provStore.Reconcile(c.Request.Context(), envOrDefault("ASSISTANT_CONNECTOR_ID", "ad-connector"), db.SystemThreatOrgID, "")
			if err != nil {
				c.JSON(http.StatusOK, gin.H{"import_enabled": req.ImportEnabled, "reconcile_error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"import_enabled": req.ImportEnabled, "reconcile": res})
		})
	}

	// SCIM 2.0 provisioning API (RFC 7644 — bearer token auth from IdPs)
	scimAPI := router.Group("/scim/v2")
	scimAPI.Use(middleware.SCIMContentType())
	scimAPI.Use(middleware.SCIMAuth(scimStore))
	{
		scimHandler := handlers.NewSCIMHandler(scimStore, logger)

		// Discovery endpoints
		scimAPI.GET("/ServiceProviderConfig", scimHandler.ServiceProviderConfig)
		scimAPI.GET("/Schemas", scimHandler.Schemas)
		scimAPI.GET("/ResourceTypes", scimHandler.ResourceTypes)

		// Admin users (IdP-provisioned administrators)
		scimAPI.GET("/AdminUsers", scimHandler.ListAdminUsers)
		scimAPI.POST("/AdminUsers", scimHandler.CreateAdminUser)
		scimAPI.GET("/AdminUsers/:id", scimHandler.GetAdminUser)
		scimAPI.PUT("/AdminUsers/:id", scimHandler.UpdateAdminUser)
		scimAPI.PATCH("/AdminUsers/:id", scimHandler.PatchAdminUser)
		scimAPI.DELETE("/AdminUsers/:id", scimHandler.DeleteAdminUser)

		// Client endpoint users (SSE desktop/mobile users)
		scimAPI.GET("/Users", scimHandler.ListClientUsers)
		scimAPI.POST("/Users", scimHandler.CreateClientUser)
		scimAPI.GET("/Users/:id", scimHandler.GetClientUser)
		scimAPI.PUT("/Users/:id", scimHandler.UpdateClientUser)
		scimAPI.PATCH("/Users/:id", scimHandler.PatchClientUser)
		scimAPI.DELETE("/Users/:id", scimHandler.DeleteClientUser)

		// Groups
		scimAPI.GET("/Groups", scimHandler.ListGroups)
		scimAPI.POST("/Groups", scimHandler.CreateGroup)
		scimAPI.GET("/Groups/:id", scimHandler.GetGroup)
		scimAPI.PUT("/Groups/:id", scimHandler.UpdateGroup)
		scimAPI.PATCH("/Groups/:id", scimHandler.PatchGroup)
		scimAPI.DELETE("/Groups/:id", scimHandler.DeleteGroup)
	}

	// Legacy gateway-facing REST API. Production gateway control uses the
	// GatewayControl gRPC service over the gateway-only mTLS listener.
	if os.Getenv("GATEWAY_REST_ENABLED") == "true" {
		gwAPI := router.Group("/api/v1/gateway")
		gwAPI.Use(middleware.GatewayAuth(gwRegistry))
		gwHandler := handlers.NewGatewayHandler(gwRegistry, policyStore, ca, logger)
		gwAPI.POST("/register", gwHandler.Register)
		gwAPI.GET("/policies", gwHandler.GetPolicies)
		gwAPI.POST("/heartbeat", gwHandler.Heartbeat)

		// mTLS certificate issuance
		gwAPI.POST("/certs/issue", gwHandler.IssueCertificate)
		gwAPI.POST("/certs/renew", gwHandler.RenewCertificate)
		gwAPI.GET("/certs/ca", gwHandler.GetCACert)

		// Policy sync (differential updates)
		gwAPI.GET("/policies/sync", gwHandler.SyncPolicies)
		gwAPI.GET("/policies/version", gwHandler.GetPolicyVersion)

		// WebSocket for push-based policy updates
		gwAPI.GET("/policies/ws", wsHub.HandleSubscribe)
	} else {
		logger.Info("Legacy gateway REST API disabled; using gRPC gateway control")
	}

	// Device-authenticated Gateway Discovery API (desktop/mobile clients use device mTLS)
	publicGWAPI := router.Group("/api/v1/gateways")
	publicGWAPI.Use(middleware.DeviceMTLSAuth(deviceStore))
	{
		gwHandler := handlers.NewGatewayHandler(gwRegistry, policyStore, ca, logger)
		publicGWAPI.GET("/available", gwHandler.ListAvailableGateways)
	}

	// Private-access ingress brokers (QUIC micro-tunnel, e.g. ad-gw) — separate
	// from selectable SWG PoPs above so clients don't offer a broker as a PoP.
	privateGWAPI := router.Group("/api/v1/private-gateways")
	privateGWAPI.Use(middleware.DeviceMTLSAuth(deviceStore))
	{
		pgwHandler := handlers.NewGatewayHandler(gwRegistry, policyStore, ca, logger)
		privateGWAPI.GET("/available", pgwHandler.ListAvailablePrivateGateways)
	}

	// Agent bootstrap endpoint. The handler itself validates device mTLS and tenant ID.
	agentAPI := router.Group("/api/v1/agent")
	{
		agentAuthHandler := handlers.NewAgentAuthHandler(deviceStore, authStore, logger)
		agentAPI.POST("/auth", agentAuthHandler.Authenticate)

		// Kerberos SSO: bind the logged-in AD user to this mTLS device so the
		// agent token carries the user's directory groups. The handler validates
		// device mTLS + SPNEGO itself (no middleware), same as /auth.
		kerberosSSOHandler := handlers.NewKerberosSSOHandler(
			kerberosValidator, deviceStore, db.NewDirectoryStore(dbConn, logger), authStore, logger)
		agentAPI.POST("/sso/kerberos", kerberosSSOHandler.Authenticate)
	}

	// Device-authenticated client runtime configuration endpoints.
	deviceClientAPI := router.Group("/api/v1/client")
	deviceClientAPI.Use(middleware.DeviceMTLSAuth(deviceStore))
	{
		clientRuntimeHandler := handlers.NewClientRuntimeHandler(clientConfigStore, deviceStore, enforcementCtl, logger)
		deviceClientAPI.POST("/bind-user", middleware.JWTAuth(authStore), middleware.RequireRole("client_user"), clientRuntimeHandler.BindUser)
		deviceClientAPI.GET("/profile", clientRuntimeHandler.GetProfile)
		deviceClientAPI.GET("/route-policies", clientRuntimeHandler.GetRoutePolicies)
		deviceClientAPI.POST("/posture", clientRuntimeHandler.ReportPosture)
		deviceClientAPI.POST("/logs", clientRuntimeHandler.ReportLogs)
		// Machine-tunnel DC-scope grant (pre-logon device tunnel; no user).
		if deviceGrantHandler != nil {
			deviceClientAPI.POST("/dc-grant", deviceGrantHandler.IssueDCGrant)
		}
	}

	// MP-brokered device enrolment (unauthenticated — the per-org enrolment secret
	// is the auth). Validates the secret → mints a one-time step-ca token.
	enrolHandler := handlers.NewEnrolHandler(db.NewEnrolSecretStore(dbConn, logger), enrolCA, deviceStore, logger)
	router.POST("/api/v1/enroll", enrolHandler.Enroll)

	// Device-authenticated legacy agent policy endpoint.
	agentPolicyAPI := router.Group("/api/v1/agent")
	agentPolicyAPI.Use(middleware.DeviceMTLSAuth(deviceStore))
	{
		agentHandler := handlers.NewAgentHandler(policyStore, logger)
		agentPolicyAPI.GET("/policies", agentHandler.GetPolicies)
	}

	// P2P Mesh API (authenticated by client JWT)
	meshAPI := router.Group("/api/v1/mesh")
	meshAPI.Use(middleware.JWTAuth(authStore))
	meshAPI.Use(middleware.RequireWriteAccess())
	{
		meshHandler := handlers.NewMeshHandler(meshCoordinator, logger)
		meshAPI.POST("/peers/register", meshHandler.RegisterPeer)
		meshAPI.DELETE("/peers/:peer_id", meshHandler.DeregisterPeer)
		meshAPI.GET("/peers", meshHandler.ListPeers)
		meshAPI.POST("/peers/:peer_id/signal", meshHandler.Signal)
		meshAPI.GET("/topology", meshHandler.GetTopology)
		meshAPI.POST("/relay/allocate", meshHandler.AllocateRelay)
	}

	// Management API (admin UI)
	adminAPI := router.Group("/api/v1/admin")
	adminAPI.Use(middleware.JWTAuth(authStore))
	adminAPI.Use(middleware.RequireWriteAccess())
	{
		adminHandler := handlers.NewAdminHandler(gwRegistry, policyStore, meshCoordinator, logger)
		adminAPI.GET("/gateways", adminHandler.ListGateways)
		adminAPI.GET("/gateways/:id", adminHandler.GetGateway)
		adminAPI.GET("/gateways/available", adminHandler.ListAvailableGateways)
		adminAPI.POST("/policies", adminHandler.CreatePolicy)
		adminAPI.PUT("/policies/:id", adminHandler.UpdatePolicy)
		adminAPI.GET("/policies", adminHandler.ListPolicies)
		adminAPI.DELETE("/policies/:id", adminHandler.DeletePolicy)
		adminAPI.GET("/mesh/topology", adminHandler.GetMeshTopology)
		adminAPI.GET("/organization/deployment-info", func(c *gin.Context) {
			orgID := c.GetString("org_id")
			if orgID == "" {
				c.JSON(401, gin.H{"error": "org_id not found in context"})
				return
			}
			info, infoErr := deviceStore.GetDeploymentInfo(c.Request.Context(), orgID)
			if infoErr != nil {
				c.JSON(500, gin.H{"error": "failed to get deployment info"})
				return
			}
			c.JSON(200, info)
		})

		// Config version control (last 10 revisions, revert capability)
		adminAPI.GET("/config/versions", adminHandler.ListConfigVersions)
		adminAPI.GET("/config/versions/:version", adminHandler.GetConfigVersion)
		adminAPI.POST("/config/revert/:version", adminHandler.RevertConfig)
		adminAPI.GET("/config/diff", adminHandler.DiffConfigVersions)

		// Config lock
		adminAPI.POST("/config/lock", adminHandler.AcquireConfigLock)
		adminAPI.DELETE("/config/lock", adminHandler.ReleaseConfigLock)
		adminAPI.GET("/config/lock", adminHandler.GetConfigLock)

		// IdP Configuration Logging (audit trail for IdP integration changes)
		idpLogsHandler := handlers.NewIdPLogsHandler(idpLogStore, logger)
		adminAPI.GET("/idp/logs", idpLogsHandler.GetIdPLogs)
		adminAPI.GET("/idp/logs/summary", idpLogsHandler.GetIdPLogSummary)
		adminAPI.GET("/idp/logs/provider/:provider_type", idpLogsHandler.GetProviderLogs)

		// IdP Test Connection (validate IdP connectivity before saving)
		idpTestHandler := handlers.NewIdPTestHandler(idpStore, idpLogStore, idBroker, logger)
		adminAPI.POST("/idp/:id/test", idpTestHandler.TestConnection)

		// AD-sync connector — web-ui-managed LDAP config + synced directory
		connectorAdminHandler := handlers.NewConnectorAdminHandler(
			db.NewConnectorStore(dbConn, logger), db.NewDirectoryStore(dbConn, logger), db.SystemThreatOrgID, logger)
		adminAPI.GET("/connectors/:connector_id/config", connectorAdminHandler.GetConnectorConfig)
		adminAPI.PUT("/connectors/:connector_id/config", connectorAdminHandler.UpdateConnectorConfig)
		adminAPI.GET("/connectors/:connector_id/users", connectorAdminHandler.ListConnectorUsers)
		adminAPI.GET("/connectors/:connector_id/groups", connectorAdminHandler.ListConnectorGroups)
		adminAPI.PATCH("/connectors/:connector_id/groups/:sid/sync", connectorAdminHandler.SetGroupSyncEnabled)

		// Apply the AD-group flow gate at startup (once, in the background) so a deploy
		// immediately reconciles native policy groups to the allowed connector groups —
		// no waiting for the next ~15m sync or a manual toggle. Backgrounded so it never
		// delays the listener / ELB health checks.
		go func() {
			bctx, bcancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer bcancel()
			connID := envOrDefault("ASSISTANT_CONNECTOR_ID", "ad-connector")
			if res, bErr := db.NewDirectoryStore(dbConn, logger).BridgeGroups(bctx, connID, db.SystemThreatOrgID); bErr != nil {
				logger.Warn("startup group bridge failed", zap.Error(bErr))
			} else {
				logger.Info("startup group bridge complete",
					zap.Int("created", res.Created), zap.Int("linked", res.Linked), zap.Int("removed", res.Removed))
			}
		}()

		// Voice/agent admin — identity bridge + explain-access + grant-access
		assistantSvc := assistant.NewService(
			db.NewDirectoryStore(dbConn, logger),
			db.NewAddressStore(dbConn, logger),
			policyStore,
			deviceStore,
			envOrDefault("ASSISTANT_CONNECTOR_ID", "ad-connector"),
			db.SystemThreatOrgID,
			logger,
		)
		// Raw DB handle for the org-aware evidence tools (block evidence,
		// category impact, security events) — resolves users across tenants.
		assistantSvc.SetDB(dbConn)
		var assistantAgent *assistant.Agent
		var assistantVoice *assistant.VoiceService
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			assistantAgent = assistant.NewAgent(assistantSvc, key, logger)
			if dg, el := os.Getenv("DEEPGRAM_API_KEY"), os.Getenv("ELEVENLABS_API_KEY"); dg != "" && el != "" {
				assistantVoice = assistant.NewVoiceService(assistantAgent, dg, el, os.Getenv("ELEVENLABS_VOICE_ID"), logger)
			} else {
				logger.Warn("DEEPGRAM_API_KEY/ELEVENLABS_API_KEY unset — assistant /voice + /speak disabled")
			}
		} else {
			logger.Warn("ANTHROPIC_API_KEY unset — assistant /chat (Claude agent) endpoint disabled")
		}
		assistantHandler := handlers.NewAssistantHandler(assistantSvc, assistantAgent, assistantVoice, logger)
		adminAPI.POST("/assistant/chat", assistantHandler.Chat)
		adminAPI.POST("/assistant/voice", assistantHandler.Voice)
		adminAPI.POST("/assistant/speak", assistantHandler.Speak)
		adminAPI.POST("/assistant/explain-access", assistantHandler.ExplainAccess)
		adminAPI.POST("/assistant/grant-access", assistantHandler.GrantAccess)
		adminAPI.POST("/assistant/bridge", assistantHandler.Bridge)
		adminAPI.POST("/assistant/seed-demo", assistantHandler.SeedDemo)

		// Device enrolment secrets — per-org wall for MP-brokered auto-enrolment.
		adminAPI.POST("/enrol-secrets", enrolHandler.GenerateSecret)
		adminAPI.GET("/enrol-secrets", enrolHandler.ListSecrets)
		adminAPI.DELETE("/enrol-secrets/:id", enrolHandler.RevokeSecret)
		// Device renewal blocks (dead-man's timer): list, manually block, clear.
		adminAPI.GET("/renewal-blocks", enrolHandler.ListRenewalBlocks)
		adminAPI.POST("/renewal-blocks", enrolHandler.BlockRenewal)
		adminAPI.DELETE("/renewal-blocks/:device_id", enrolHandler.ClearRenewalBlock)
	}

	// ── Audit middleware — log all mutations to audit trail ──
	router.Use(middleware.AuditMiddleware(auditLog))

	// TLS Scanner & ApexAdversary Outreach API
	scannerAPI := router.Group("/api/v1/scanner")
	scannerAPI.Use(middleware.JWTAuth(authStore))
	scannerAPI.Use(middleware.RequireWriteAccess())
	{
		scanHandler := handlers.NewScannerHandler(tlsScanner, outreachEngine, auditLog, logger)
		scannerAPI.POST("/sources", scanHandler.AddSource)
		scannerAPI.GET("/sources", scanHandler.ListSources)
		scannerAPI.DELETE("/sources/:id", scanHandler.RemoveSource)
		scannerAPI.POST("/scan", scanHandler.ScanAll)
		scannerAPI.POST("/scan/host", scanHandler.ScanHost)
		scannerAPI.GET("/results", scanHandler.ListResults)
		scannerAPI.GET("/results/:id", scanHandler.GetResult)
		scannerAPI.POST("/outreach/:id", scanHandler.SendOutreach)
		scannerAPI.GET("/opportunities", scanHandler.ListOpportunities)
		scannerAPI.GET("/opportunities/:id", scanHandler.GetOpportunity)
		scannerAPI.PUT("/opportunities/:id/status", scanHandler.UpdateOpportunityStatus)
	}

	// Audit Logs API
	auditAPI := router.Group("/api/v1/audit")
	auditAPI.Use(middleware.JWTAuth(authStore))
	auditAPI.Use(middleware.RequireWriteAccess())
	{
		auditHandler := handlers.NewAuditHandler(auditLog, logger)
		auditAPI.GET("/logs", auditHandler.ListAuditLogs)
		auditAPI.POST("/logs/query", auditHandler.QueryAuditLogs)
	}

	// Dot1X HTTPS-based AAA API (branch office switches call these endpoints)
	dot1xAPI := router.Group("/api/v1/dot1x")
	dot1xAPI.Use(middleware.GatewayAuth(gwRegistry))
	{
		dot1xHandler := handlers.NewDot1XHandler(dot1xAuth, sessionEnforcer, enforcementCtl, auditLog, logger)
		dot1xAPI.POST("/authenticate", dot1xHandler.Authenticate)
		dot1xAPI.POST("/authorize", dot1xHandler.Authorize)
		dot1xAPI.POST("/accounting", dot1xHandler.Accounting)
		dot1xAPI.GET("/sessions", dot1xHandler.ListSessions)
		dot1xAPI.GET("/sessions/:id", dot1xHandler.GetSession)
		dot1xAPI.POST("/sessions/:id/disconnect", dot1xHandler.DisconnectSession)
		dot1xAPI.POST("/sessions/:id/quarantine", dot1xHandler.QuarantineSession)
		// External risk signal (SWG/NDR/deception/analyst) → configured enforcement.
		dot1xAPI.POST("/sessions/:id/risk-signal", dot1xHandler.IngestRiskSignal)
		dot1xAPI.POST("/mac/register", dot1xHandler.RegisterMAC)
		dot1xAPI.DELETE("/mac/:mac", dot1xHandler.RemoveMAC)
		dot1xAPI.GET("/mac", dot1xHandler.ListMACs)
	}

	// SWG Domain-Risk PDP — the SWG PEP posts new public-domain events and gets
	// an enforcement verdict (default-deny). Scorer is nil until P2 (the Claude
	// risk agent); a cache MISS returns a provisional monitor/pending verdict.
	riskStore := risk.NewStore(dbConn.DB)
	itsmStore := db.NewITSMStore(dbConn, logger)

	pdpAPI := router.Group("/api/v1/pdp")
	pdpAPI.Use(middleware.GatewayAuth(gwRegistry))
	{
		pdpHandler := handlers.NewPDPHandler(risk.NewService(riskStore, nil, logger), logger)
		pdpAPI.POST("/domain-event", pdpHandler.DomainEvent)
	}

	// Internal ITSM — native service/change requests (a 3rd routing target
	// beside JIRA/ServiceNow), operator+tenant scoped. Console-facing (JWT).
	itsmAPI := router.Group("/api/v1/admin/itsm")
	itsmAPI.Use(middleware.JWTAuth(authStore))
	{
		itsmHandler := handlers.NewITSMHandler(itsmStore, logger)
		itsmAPI.GET("/tickets", itsmHandler.ListTickets)
		itsmAPI.POST("/tickets", itsmHandler.CreateTicket)
		itsmAPI.POST("/tickets/:id/status", itsmHandler.UpdateTicketStatus)
	}

	// Agentic risk-ops — the decision log + create-policy-from-log and
	// create-ticket-from-log, operator+tenant scoped.
	riskOpsAPI := router.Group("/api/v1/admin/risk")
	riskOpsAPI.Use(middleware.JWTAuth(authStore))
	{
		opsHandler := handlers.NewRiskOpsHandler(riskStore, itsmStore, logger)
		riskOpsAPI.GET("/decisions", opsHandler.ListDecisions)
		riskOpsAPI.POST("/decisions/:id/promote-policy", opsHandler.PromoteToPolicy)
		riskOpsAPI.POST("/decisions/:id/create-ticket", opsHandler.TicketFromDecision)
	}

	// Advanced Security Group Tags (SGT) & Branch Sites API
	sgtAPI := router.Group("/api/v1/sgt")
	sgtAPI.Use(middleware.JWTAuth(authStore))
	sgtAPI.Use(middleware.RequireWriteAccess())
	{
		sgtHandler := handlers.NewSegmentHandler(sgtStore, logger)
		sgtAPI.GET("/tags", sgtHandler.ListTags)
		sgtAPI.GET("/tags/:id", sgtHandler.GetTag)
		sgtAPI.POST("/tags", sgtHandler.CreateTag)
		sgtAPI.PUT("/tags/:id", sgtHandler.UpdateTag)
		sgtAPI.DELETE("/tags/:id", sgtHandler.DeleteTag)
		sgtAPI.GET("/policies", sgtHandler.ListPolicies)
		sgtAPI.GET("/policies/:id", sgtHandler.GetPolicy)
		sgtAPI.POST("/policies", sgtHandler.CreatePolicy)
		sgtAPI.PUT("/policies/:id", sgtHandler.UpdatePolicy)
		sgtAPI.DELETE("/policies/:id", sgtHandler.DeletePolicy)
		sgtAPI.GET("/matrix", sgtHandler.GetMatrix)
		sgtAPI.POST("/classify", sgtHandler.Classify)
		sgtAPI.GET("/sites", sgtHandler.ListSites)
		sgtAPI.GET("/sites/:id", sgtHandler.GetSite)
		sgtAPI.POST("/sites", sgtHandler.CreateSite)
		sgtAPI.PUT("/sites/:id", sgtHandler.UpdateSite)
		sgtAPI.DELETE("/sites/:id", sgtHandler.DeleteSite)
	}

	// SDN Whitebox Switch Management API
	sdnAPI := router.Group("/api/v1/sdn")
	sdnAPI.Use(middleware.JWTAuth(authStore))
	sdnAPI.Use(middleware.RequireWriteAccess())
	{
		sdnHandler := handlers.NewSDNHandler(sdnManager, logger)
		sdnAPI.GET("/switches", sdnHandler.ListSwitches)
		sdnAPI.GET("/switches/:id", sdnHandler.GetSwitch)
		sdnAPI.POST("/switches", sdnHandler.RegisterSwitch)
		sdnAPI.DELETE("/switches/:id", sdnHandler.DeregisterSwitch)
		sdnAPI.POST("/switches/:id/heartbeat", sdnHandler.SwitchHeartbeat)
		sdnAPI.POST("/switches/:id/config", sdnHandler.PushConfig)
		sdnAPI.GET("/vendors", sdnHandler.ListVendors)
		sdnAPI.GET("/vendors/:id", sdnHandler.GetVendor)
	}

	// Identity Broker API (IdP federation, token exchange, sessions)
	idAPI := router.Group("/api/v1/identity")
	idAPI.Use(middleware.JWTAuth(authStore))
	idAPI.Use(middleware.RequireWriteAccess())
	{
		idHandler := handlers.NewIdentityBrokerHandler(idBroker, idpStore, logger)
		idAPI.GET("/providers", idHandler.ListIdPs)
		idAPI.GET("/providers/:id", idHandler.GetIdP)
		idAPI.POST("/providers", idHandler.CreateIdP)
		idAPI.PUT("/providers/:id", idHandler.UpdateIdP)
		idAPI.DELETE("/providers/:id", idHandler.DeleteIdP)
		idAPI.GET("/auth-profiles", idHandler.ListAuthProfiles)
		idAPI.PUT("/auth-profiles", idHandler.UpdateAuthProfiles)
		idAPI.POST("/token/exchange", idHandler.ExchangeToken)
		idAPI.GET("/sessions", idHandler.ListSessions)
		idAPI.GET("/sessions/:id", idHandler.GetSession)
		idAPI.DELETE("/sessions/:id", idHandler.RevokeSession)
	}

	// Feature Licensing API
	featureAPI := router.Group("/api/v1/features")
	featureAPI.Use(middleware.JWTAuth(authStore))
	featureAPI.Use(middleware.RequireWriteAccess())
	{
		featHandler := handlers.NewFeatureHandler(featureStore, orgPlan, logger)
		featureAPI.GET("", featHandler.ListFeatures)
		featureAPI.GET("/:id", featHandler.GetFeature)
		featureAPI.PUT("/:id/toggle", featHandler.ToggleFeature)
		featureAPI.POST("/:id/trial", featHandler.StartTrial)
	}

	// Tenants API — consolidated MSP overview + per-tenant dashboards. Cross-tenant
	// by design (manager-of-managers). Gated to admin roles.
	tenantHandler := handlers.NewTenantHandler(db.NewTenantStore(dbConn, logger), logger)
	tenantAPI := router.Group("/api/v1/admin/tenants")
	tenantAPI.Use(middleware.JWTAuth(authStore))
	tenantAPI.Use(middleware.RequireWriteAccess())
	{
		tenantAPI.GET("", tenantHandler.ListTenants)
		tenantAPI.GET("/:id", tenantHandler.GetTenant)
		tenantAPI.GET("/:id/entitlements", tenantHandler.GetEntitlements)
	}
	// Operator rollup for the ApexAegis → operators → tenants partner ladder.
	operatorAPI := router.Group("/api/v1/admin/operators")
	operatorAPI.Use(middleware.JWTAuth(authStore))
	operatorAPI.Use(middleware.RequireWriteAccess())
	operatorAPI.GET("", tenantHandler.ListOperators)
	// Subscription tiers (store catalog + billing).
	tierAPI := router.Group("/api/v1/admin/tiers")
	tierAPI.Use(middleware.JWTAuth(authStore))
	tierAPI.Use(middleware.RequireWriteAccess())
	{
		tierAPI.GET("", tenantHandler.ListTiers)
	}
	// Cross-tenant policy detail — the /policies/:id deep-link the assistant returns.
	policyDetailAPI := router.Group("/api/v1/admin/policy")
	policyDetailAPI.Use(middleware.JWTAuth(authStore))
	policyDetailAPI.Use(middleware.RequireWriteAccess())
	{
		policyDetailAPI.GET("/:id", tenantHandler.GetPolicy)
	}
	// Consolidated ghosted apps across all tenants (per-tenant is in tenant detail).
	ghostedAdminAPI := router.Group("/api/v1/admin/ghosted")
	ghostedAdminAPI.Use(middleware.JWTAuth(authStore))
	ghostedAdminAPI.Use(middleware.RequireWriteAccess())
	{
		ghostedAdminAPI.GET("", tenantHandler.ListGhosted)
	}
	// Cross-tenant device inventory for the Device Enrolment page + posture modal.
	deviceInvAPI := router.Group("/api/v1/admin/devices-inventory")
	deviceInvAPI.Use(middleware.JWTAuth(authStore))
	deviceInvAPI.Use(middleware.RequireWriteAccess())
	{
		deviceInvAPI.GET("", tenantHandler.ListDevices)
	}
	// Email a dashboard report (body composed client-side) via SES.
	reportAPI := router.Group("/api/v1/admin/report")
	reportAPI.Use(middleware.JWTAuth(authStore))
	reportAPI.Use(middleware.RequireWriteAccess())
	{
		reportAPI.POST("/email", tenantHandler.EmailReport)
	}
	// Device posture profile (per tenant; honors X-Scope-Tenant-ID for super_admin).
	postureAPI := router.Group("/api/v1/admin/posture-profile")
	postureAPI.Use(middleware.JWTAuth(authStore))
	postureAPI.Use(middleware.RequireWriteAccess())
	{
		postureAPI.GET("", tenantHandler.GetPostureProfile)
		postureAPI.PUT("", tenantHandler.UpdatePostureProfile)
	}

	// RBAC API — custom roles with per-page access toggles, tenant-scoped or
	// global (MSP). Governs console page access, not tenant data isolation.
	rbacAPI := router.Group("/api/v1/admin/rbac")
	rbacAPI.Use(middleware.JWTAuth(authStore))
	rbacAPI.Use(middleware.RequireWriteAccess())
	{
		rbacHandler := handlers.NewRBACHandler(db.NewRBACStore(dbConn, logger), logger)
		rbacAPI.GET("/tenants", rbacHandler.ListTenants)
		rbacAPI.GET("/pages", rbacHandler.ListPages)
		rbacAPI.GET("/effective-pages", rbacHandler.EffectivePages)
		rbacAPI.GET("/roles", rbacHandler.ListRoles)
		rbacAPI.POST("/roles", rbacHandler.CreateRole)
		rbacAPI.PUT("/roles/:id", rbacHandler.UpdateRole)
		rbacAPI.DELETE("/roles/:id", rbacHandler.DeleteRole)
	}

	// Security Profiles API
	profileAPI := router.Group("/api/v1/profiles")
	profileAPI.Use(middleware.JWTAuth(authStore))
	profileAPI.Use(middleware.RequireWriteAccess())
	{
		profHandler := handlers.NewProfileHandler(profileStore, logger)
		profileAPI.GET("/:type", profHandler.ListProfiles)
		profileAPI.POST("/:type", profHandler.CreateProfile)
		profileAPI.GET("/:type/:id", profHandler.GetProfile)
		profileAPI.PUT("/:type/:id", profHandler.UpdateProfile)
		profileAPI.DELETE("/:type/:id", profHandler.DeleteProfile)
		profileAPI.PUT("/:type/:id/toggle", profHandler.ToggleProfile)
	}

	// GhostedApps Detection API
	ghostAPI := router.Group("/api/v1/ghosted-apps")
	ghostAPI.Use(middleware.JWTAuth(authStore))
	ghostAPI.Use(middleware.RequireWriteAccess())
	{
		ghostHandler := handlers.NewGhostedAppsHandler(logger)
		ghostAPI.GET("", ghostHandler.ListAgents)
		ghostAPI.GET("/:id", ghostHandler.GetAgent)
		ghostAPI.POST("/rescan", ghostHandler.Rescan)
		ghostAPI.GET("/scan/last", ghostHandler.GetLastScan)
	}

	// Client Configuration API (Phase 6 Option B)
	clientConfigHandler := handlers.NewClientConfigHandler(clientConfigStore, logger)
	ccAdminAPI := router.Group("/api/v1/admin/client-config")
	ccAdminAPI.Use(middleware.JWTAuth(authStore))
	ccAdminAPI.Use(middleware.RequireWriteAccess())
	{
		ccAdminAPI.GET("", clientConfigHandler.ListClientConfigs)
		ccAdminAPI.GET("/:group_id", clientConfigHandler.GetClientConfig)
		ccAdminAPI.POST("", clientConfigHandler.CreateClientConfig)
		ccAdminAPI.PUT("/:group_id", clientConfigHandler.UpdateClientConfig)
		ccAdminAPI.DELETE("/:group_id", clientConfigHandler.DeleteClientConfig)
		ccAdminAPI.GET("/audit-logs", clientConfigHandler.GetAuditLogs)
		ccAdminAPI.POST("/validate", clientConfigHandler.ValidateConfig)
	}

	// ── DNS Threat Intelligence API (Phase 6 DNS Filtering) ──
	// Threat intel sourced from: VirusTotal, AlienVault OTX, URLScan.io
	threatStore := db.NewThreatStore(dbConn, logger)

	// Initialize fetcher with API keys from environment
	vtAPIKey := os.Getenv("VIRUSTOTAL_API_KEY")
	otxAPIKey := os.Getenv("OTX_API_KEY")
	// OTX requires LevelBlue USM integration, skip for now
	urlscanAPIKey := os.Getenv("URLSCAN_API_KEY")

	threatFetcher := threat_intel.NewThreatFetcher(otxAPIKey, vtAPIKey, urlscanAPIKey, logger)
	syncService := threat_intel.NewSyncService(threatStore, threatFetcher, logger)
	syncService.Start(context.Background())

	threatIntelHandler := handlers.NewThreatIntelHandler(threatStore, syncService, logger)
	threatAPI := router.Group("/api/v1/admin/threat-intel")
	threatAPI.Use(middleware.JWTAuth(authStore))
	threatAPI.Use(middleware.RequireWriteAccess())
	{
		threatAPI.GET("/sources", threatIntelHandler.ListSources)
		threatAPI.GET("/stats", threatIntelHandler.GetSourceStats)
		threatAPI.POST("/sync", threatIntelHandler.ManualSync)
		threatAPI.POST("/lookup", threatIntelHandler.LookupThreat)
		threatAPI.POST("/cleanup", threatIntelHandler.EvictStale)
	}

	logger.Info("threat intelligence API initialized",
		zap.Bool("virustotal_enabled", vtAPIKey != ""),
		zap.Bool("otx_enabled", otxAPIKey != ""),
		zap.Bool("urlscan_enabled", urlscanAPIKey != ""),
	)

	// ── DNS Query Logging API ──
	dnsLogStore := db.NewDNSLogStore(dbConn, logger)
	dnsLogsHandler := handlers.NewDNSLogsHandler(dnsLogStore, logger)
	dnsLogsAPI := router.Group("/api/v1/admin/dns-logs")
	dnsLogsAPI.Use(middleware.JWTAuth(authStore))
	dnsLogsAPI.Use(middleware.RequireWriteAccess())
	{
		dnsLogsAPI.GET("", dnsLogsHandler.GetDNSLogs)
		dnsLogsAPI.GET("/summary", dnsLogsHandler.GetDNSSummary)
		dnsLogsAPI.GET("/stats", dnsLogsHandler.GetDNSLogsStats)
		dnsLogsAPI.POST("/cleanup", dnsLogsHandler.DeleteOldLogs)
	}

	logger.Info("DNS logging API initialized")

	// Security Validation API (container-based test infrastructure)
	validationAPI := router.Group("/api/v1/validation")
	validationAPI.Use(middleware.JWTAuth(authStore))
	validationAPI.Use(middleware.RequireWriteAccess())
	{
		valHandler := handlers.NewValidationHandler(validationEngine, logger)
		validationAPI.GET("/tests", valHandler.ListTests)
		validationAPI.GET("/environments", valHandler.ListEnvironments)
		validationAPI.POST("/provision", valHandler.ProvisionEnvironment)
		validationAPI.GET("/environments/:id", valHandler.GetEnvironmentStatus)
		validationAPI.DELETE("/environments/:id", valHandler.DestroyEnvironment)
		validationAPI.POST("/environments/:id/run", valHandler.RunTests)
		validationAPI.GET("/runs/:runId", valHandler.GetRunResult)
		validationAPI.POST("/simulate", valHandler.SimulatePolicy)
	}

	// Security API — code signing, enrollment tokens, command signing
	securityAPI := router.Group("/api/v1/security")
	securityAPI.Use(middleware.JWTAuth(authStore))
	securityAPI.Use(middleware.RequireWriteAccess())
	{
		secHandler := handlers.NewSecurityHandler(codeSigningSvc, enrollmentSvc, commandSigningSvc, logger)

		// Code signing
		securityAPI.POST("/sign", secHandler.SignArtifact)
		securityAPI.POST("/verify", secHandler.VerifyArtifact)
		securityAPI.GET("/artifacts", secHandler.ListArtifacts)
		securityAPI.GET("/keys", secHandler.ListSigningKeys)
		securityAPI.GET("/keys/:id", secHandler.GetPublicKey)

		// Device enrollment is certificate-driven. The portal/MDM issues device
		// certificates; runtime registration happens through /api/v1/agent/auth
		// using mTLS, not one-time registration tokens.
		securityAPI.GET("/enrollment/agents", secHandler.ListEnrolledAgents)
		securityAPI.DELETE("/enrollment/agents/:id", secHandler.DeactivateAgent)

		// Command signing
		securityAPI.POST("/commands/issue", secHandler.IssueCommand)
		securityAPI.POST("/commands/verify", secHandler.VerifyCommand)
		securityAPI.GET("/commands", secHandler.ListCommands)
		securityAPI.GET("/commands/pending/:targetId", secHandler.GetPendingCommands)
	}

	listenAddr := envOrDefault("LISTEN_ADDR", ":443")
	deployMode := envOrDefault("DEPLOY_MODE", "cloud")

	// ── Start optional dedicated mTLS server for gateway-to-mgmt-plane communication ──
	// Production gateway control uses gRPC behind a gateway-only mTLS ALB/NLB.
	// Keep this legacy REST mTLS listener disabled unless a lab deployment needs it.
	if os.Getenv("MTLS_ENABLED") == "true" {
		mtlsAddr := envOrDefault("MTLS_LISTEN_ADDR", listenAddr)
		if mtlsAddr == listenAddr {
			logger.Info("mTLS enabled on shared REST+gRPC listener", zap.String("addr", listenAddr))
		} else {
			go startMTLSServer(ctx, ca, gwRegistry, policyStore, meshCoordinator, wsHub, logger)
			logger.Info("dedicated mTLS server enabled", zap.String("addr", mtlsAddr))
		}
	} else {
		logger.Info("mTLS server disabled (set MTLS_ENABLED=true to enable)")
	}

	// ── Multiplex gRPC + HTTP on a single port (Railway only exposes one port) ──
	// gRPC requests carry "Content-Type: application/grpc" — cmux routes them
	// to the gRPC server; everything else goes to the Gin HTTP handler.
	logger.Info("Starting multiplexed gRPC+HTTP listener",
		zap.String("addr", listenAddr),
		zap.String("deploy_mode", deployMode),
	)

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Fatal("Failed to bind listener", zap.Error(err))
	}

	mux := cmux.New(lis)
	grpcLis := mux.MatchWithWriters(
		cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"),
	)
	httpLis := mux.Match(cmux.Any())

	// DNS security: per-group policy + threat-feed sync served to gateways over
	// the same gRPC server. Feeds come from DNS_SECURITY_FEEDS ("category=url,...");
	// default to abuse.ch URLhaus (malware) when unset.
	dnsFeedProviders := threatfeed.ParseFeedSpecs(os.Getenv("DNS_SECURITY_FEEDS"))
	if len(dnsFeedProviders) == 0 {
		dnsFeedProviders = []threatfeed.Provider{&threatfeed.DomainListProvider{
			ProviderName: "urlhaus",
			Cat:          "malicious",
			URL:          "https://urlhaus.abuse.ch/downloads/hostfile/",
		}}
	}
	dnsFeedStore := threatfeed.NewStore(&threatfeed.Aggregator{Providers: dnsFeedProviders})
	go dnsFeedStore.Run(ctx, 30*time.Minute)
	dnsSecurityServer := &dnssec.Server{
		Policies: dnssec.StorePolicySource{Store: clientConfigStore},
		Feed:     dnsFeedStore,
		Devices:  deviceStore,
	}

	// gRPC server
	grpcSrv := grpcserver.NewServer(grpcserver.Config{
		CertFile:              os.Getenv("GRPC_TLS_CERT_FILE"),
		KeyFile:               os.Getenv("GRPC_TLS_KEY_FILE"),
		CACertFile:            os.Getenv("GRPC_TLS_CA_FILE"),
		DevMode:               os.Getenv("GRPC_TLS_ENABLED") != "true",
		RequireClientIdentity: os.Getenv("GRPC_REQUIRE_CLIENT_IDENTITY") == "true",
	}, grpcserver.Deps{
		PolicyStore: policyStore,
		Registry:    gwRegistry,
		Logger:      logger,
		DNSSecurity: dnsSecurityServer,
	})
	go func() {
		if err := grpcSrv.ServeListener(ctx, grpcLis); err != nil {
			logger.Error("gRPC server error", zap.Error(err))
		}
	}()

	// HTTP server
	server := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info("Management plane HTTP server starting", zap.String("addr", listenAddr))
		if err := server.Serve(httpLis); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server error", zap.Error(err))
		}
	}()

	// Start cmux dispatcher
	go func() {
		if err := mux.Serve(); err != nil && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
			logger.Error("cmux error", zap.Error(err))
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down management plane...")
	close(jwksStop)
	cancel()
	dbConn.Close()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)
	fmt.Println("Management plane stopped")
}

// startMTLSServer runs a separate TLS listener that requires client certificates
// signed by our internal CA. Gateways use this for secure policy sync.
func startMTLSServer(
	ctx context.Context,
	ca *auth.CertificateAuthority,
	gwRegistry *gateway.Registry,
	policyStore policy.PolicyStore,
	meshCoordinator *gateway.MeshCoordinator,
	wsHub *websocket.Hub,
	logger *zap.Logger,
) {
	mtlsAddr := envOrDefault("MTLS_LISTEN_ADDR", ":443")
	tlsConfig := ca.ServerTLSConfig()

	router := gin.New()
	router.Use(middleware.RequestID())
	router.Use(middleware.SafeRecovery())
	router.Use(middleware.ErrorHandler())
	router.Use(middleware.MTLSIdentity())

	gwHandler := handlers.NewGatewayHandler(gwRegistry, policyStore, ca, logger)
	router.GET("/mtls/v1/policies", gwHandler.GetPolicies)
	router.GET("/mtls/v1/policies/sync", gwHandler.SyncPolicies)
	router.POST("/mtls/v1/heartbeat", gwHandler.Heartbeat)
	router.GET("/mtls/v1/policies/ws", wsHub.HandleSubscribe)

	server := &http.Server{
		Addr:              mtlsAddr,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("mTLS server starting (gateway ↔ management plane)", zap.String("addr", mtlsAddr))
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		logger.Error("mTLS server error", zap.Error(err))
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// startPostureConnectors wires optional EDR/MDM posture connectors (env-gated) and
// runs them in the background. Each external verdict is written as a
// device_posture_report, so the compliance claim + gateway gate act on it exactly
// like a self-reported one. No-op unless credentials are configured.
func startPostureConnectors(ctx context.Context, devices *db.DeviceStore, tenants *db.TenantStore, logger *zap.Logger) {
	var connectors []posture.Connector
	if os.Getenv("CROWDSTRIKE_CLIENT_ID") != "" {
		cs := posture.NewCrowdStrikeZTA(posture.CrowdStrikeConfig{
			ClientID:     os.Getenv("CROWDSTRIKE_CLIENT_ID"),
			ClientSecret: os.Getenv("CROWDSTRIKE_CLIENT_SECRET"),
			BaseURL:      os.Getenv("CROWDSTRIKE_BASE_URL"),
		}, logger)
		if cs.Enabled() {
			connectors = append(connectors, cs)
		}
	}
	if len(connectors) == 0 {
		return
	}
	save := func(ctx context.Context, orgID string, v posture.Verdict) error {
		raw, _ := json.Marshal(map[string]any{"source": v.Source, "score": v.Score, "signals": v.Signals})
		return devices.SavePostureReport(ctx, orgID, v.DeviceID, db.DevicePostureReport{
			CheckedAt: time.Now(), Compliant: v.Compliant, Score: v.Score,
			AntivirusName: v.Source, Raw: raw,
		})
	}
	orgs := func(ctx context.Context) ([]string, error) {
		summaries, err := tenants.ListTenantSummaries(ctx, db.TenantScope{})
		if err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(summaries))
		for _, s := range summaries {
			ids = append(ids, s.ID)
		}
		return ids, nil
	}
	go posture.NewRunner(save, orgs, 5*time.Minute, logger, connectors...).Run(ctx)
}

func newLogger() (*zap.Logger, error) {
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		return zap.NewProduction()
	}

	level := zapcore.InfoLevel
	if strings.EqualFold(os.Getenv("LOG_LEVEL"), "debug") {
		level = zapcore.DebugLevel
	}

	core := &cefCore{
		out:     os.Stderr,
		mu:      &sync.Mutex{},
		enabler: zap.LevelEnablerFunc(func(l zapcore.Level) bool { return l >= level }),
	}

	return zap.New(
		core,
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.FatalLevel),
	), nil
}

type cefCore struct {
	mu      *sync.Mutex
	out     *os.File
	enabler zapcore.LevelEnabler
	fields  []zapcore.Field
}

func (c *cefCore) Enabled(level zapcore.Level) bool {
	return c.enabler.Enabled(level)
}

func (c *cefCore) With(fields []zapcore.Field) zapcore.Core {
	next := *c
	next.fields = append(append([]zapcore.Field{}, c.fields...), fields...)
	return &next
}

func (c *cefCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

func (c *cefCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	allFields := append(append([]zapcore.Field{}, c.fields...), fields...)

	extensions := []string{
		"end=" + strconv.FormatInt(entry.Time.UnixMilli(), 10),
		"msg=" + cefEscape(entry.Message),
		"sourceServiceName=management-plane",
	}
	if entry.Caller.Defined {
		extensions = append(extensions, "cs1Label=caller", "cs1="+cefEscape(entry.Caller.TrimmedPath()))
	}
	if entry.Stack != "" {
		extensions = append(extensions, "cs2Label=stack", "cs2="+cefEscape(entry.Stack))
	}
	for _, field := range allFields {
		key := cefKey(field.Key)
		if key == "" {
			continue
		}
		extensions = append(extensions, key+"="+cefEscape(cefFieldValue(field)))
	}

	line := fmt.Sprintf("CEF:0|ApexAegis|ManagementPlane|1.0|%s|%s|%d|%s\n",
		cefHeaderEscape(entry.Level.String()),
		cefHeaderEscape(entry.Message),
		cefSeverity(entry.Level),
		strings.Join(extensions, " "),
	)

	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.out.WriteString(line)
	return err
}

func (c *cefCore) Sync() error {
	return c.out.Sync()
}

func cefSeverity(level zapcore.Level) int {
	switch {
	case level >= zapcore.FatalLevel:
		return 10
	case level >= zapcore.ErrorLevel:
		return 8
	case level >= zapcore.WarnLevel:
		return 6
	case level >= zapcore.InfoLevel:
		return 3
	default:
		return 1
	}
}

func cefFieldValue(field zapcore.Field) string {
	switch field.Type {
	case zapcore.StringType:
		return field.String
	case zapcore.ErrorType:
		if err, ok := field.Interface.(error); ok && err != nil {
			return err.Error()
		}
	case zapcore.BoolType:
		return strconv.FormatBool(field.Integer == 1)
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		return strconv.FormatInt(field.Integer, 10)
	case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type, zapcore.UintptrType:
		return strconv.FormatUint(uint64(field.Integer), 10)
	case zapcore.Float64Type:
		return strconv.FormatFloat(math.Float64frombits(uint64(field.Integer)), 'f', -1, 64)
	case zapcore.Float32Type:
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(field.Integer))), 'f', -1, 32)
	case zapcore.DurationType:
		return time.Duration(field.Integer).String()
	case zapcore.TimeType:
		return time.Unix(0, field.Integer).UTC().Format(time.RFC3339Nano)
	default:
		if field.Interface != nil {
			return fmt.Sprint(field.Interface)
		}
	}
	return field.String
}

func cefKey(key string) string {
	var b strings.Builder
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cefHeaderEscape(value string) string {
	return strings.NewReplacer("\\", "\\\\", "|", "\\|", "\n", " ", "\r", " ").Replace(value)
}

func cefEscape(value string) string {
	return strings.NewReplacer("\\", "\\\\", "=", "\\=", "|", "\\|", "\n", "\\n", "\r", "\\r").Replace(value)
}
