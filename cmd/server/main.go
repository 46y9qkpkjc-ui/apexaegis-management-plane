package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/soheilhy/cmux"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/api/handlers"
	"github.com/zcp/management-plane/internal/api/middleware"
	"github.com/zcp/management-plane/internal/audit"
	"github.com/zcp/management-plane/internal/auth"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/dot1x"
	"github.com/zcp/management-plane/internal/gateway"
	"github.com/zcp/management-plane/internal/grpcserver"
	"github.com/zcp/management-plane/internal/identity"
	"github.com/zcp/management-plane/internal/policy"
	"github.com/zcp/management-plane/internal/scanner"
	"github.com/zcp/management-plane/internal/sdn"
	"github.com/zcp/management-plane/internal/security"
	"github.com/zcp/management-plane/internal/segment"
	"github.com/zcp/management-plane/internal/validation"
	"github.com/zcp/management-plane/internal/websocket"
)

func main() {
	logger, _ := zap.NewProduction()
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

	dbConn, err := db.Open(db.Config{DSN: databaseURL}, logger)
	if err != nil {
		logger.Fatal("Failed to connect to CockroachDB Cloud", zap.Error(err))
	}

	// Run schema migrations on startup (idempotent — skips already-applied)
	migrationsDir := envOrDefault("MIGRATIONS_DIR", "internal/db/migrations")
	if migErr := dbConn.Migrate(migrationsDir); migErr != nil {
		fmt.Fprintf(os.Stderr, "MIGRATION ERROR: %v\n", migErr)
		logger.Fatal("Schema migration failed", zap.Error(migErr))
	}

	// ── Stores (CockroachDB Cloud backed) ──
	policyStore := db.NewPolicyStore(dbConn, logger)
	policyStore.LoadDefaults()

	featureStore := db.NewFeatureStore(dbConn)
	profileStore := db.NewProfileStore(dbConn)

	// ── Auth store (user authentication + JWT) ──
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		logger.Fatal("JWT_SECRET is required — set a strong random secret (32+ chars)")
	}
	authStore := db.NewAuthStore(dbConn, []byte(jwtSecret), logger)

	// ── SCIM store (admin + client user provisioning) ──
	scimStore := db.NewSCIMStore(dbConn, logger)

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

	// ── Advanced Security Group Tags (SGT) with multi-domain context ──
	sgtStore := segment.NewStore(logger)

	// ── Identity Broker (IdP federation + attribute normalization) ──
	idBroker := identity.NewBroker(logger)
	idpStore := db.NewIdPStore(dbConn, logger)
	idBroker.SetPersister(idpStore)

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
	enrollmentSvc := security.NewEnrollmentService(logger)
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
		ssoHandler := handlers.NewSSOHandler(idBroker, authStore, logger)
		authAPI.GET("/sso/providers", ssoHandler.ListSSOProviders)
		authAPI.GET("/sso/:idp_id/authorize", ssoHandler.Authorize)
		authAPI.GET("/sso/callback", ssoHandler.CallbackRedirect)
		authAPI.POST("/sso/callback", ssoHandler.Callback)
	}

	// User Management API (admin-only)
	userAPI := router.Group("/api/v1/users")
	userAPI.Use(middleware.JWTAuth(authStore))
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
	{
		clientAPI.GET("", func(c *gin.Context) {
			filter := c.Query("search")
			users, _, err := scimStore.ListClientUsers(c.Request.Context(), filter, 1, 200)
			if err != nil {
				c.JSON(500, gin.H{"error": "failed to list client users"})
				return
			}
			if users == nil {
				users = []db.SCIMUser{}
			}
			c.JSON(200, users)
		})
	}

	// SCIM 2.0 provisioning API (RFC 7644 — bearer token auth from IdPs)
	scimAPI := router.Group("/scim/v2")
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
		scimAPI.DELETE("/AdminUsers/:id", scimHandler.DeleteAdminUser)

		// Client endpoint users (SSE desktop/mobile users)
		scimAPI.GET("/Users", scimHandler.ListClientUsers)
		scimAPI.POST("/Users", scimHandler.CreateClientUser)
		scimAPI.GET("/Users/:id", scimHandler.GetClientUser)
		scimAPI.PUT("/Users/:id", scimHandler.UpdateClientUser)
		scimAPI.DELETE("/Users/:id", scimHandler.DeleteClientUser)

		// Groups
		scimAPI.GET("/Groups", scimHandler.ListGroups)
		scimAPI.POST("/Groups", scimHandler.CreateGroup)
		scimAPI.GET("/Groups/:id", scimHandler.GetGroup)
		scimAPI.PUT("/Groups/:id", scimHandler.UpdateGroup)
		scimAPI.DELETE("/Groups/:id", scimHandler.DeleteGroup)
	}

	// Gateway-facing API (authenticated by gateway API key or mTLS)
	gwAPI := router.Group("/api/v1/gateway")
	gwAPI.Use(middleware.GatewayAuth(gwRegistry))
	{
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
	}

	// P2P Mesh API (authenticated by client JWT)
	meshAPI := router.Group("/api/v1/mesh")
	meshAPI.Use(middleware.JWTAuth(authStore))
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

		// Config version control (last 10 revisions, revert capability)
		adminAPI.GET("/config/versions", adminHandler.ListConfigVersions)
		adminAPI.GET("/config/versions/:version", adminHandler.GetConfigVersion)
		adminAPI.POST("/config/revert/:version", adminHandler.RevertConfig)
		adminAPI.GET("/config/diff", adminHandler.DiffConfigVersions)

		// Config lock
		adminAPI.POST("/config/lock", adminHandler.AcquireConfigLock)
		adminAPI.DELETE("/config/lock", adminHandler.ReleaseConfigLock)
		adminAPI.GET("/config/lock", adminHandler.GetConfigLock)
	}

	// ── Audit middleware — log all mutations to audit trail ──
	router.Use(middleware.AuditMiddleware(auditLog))

	// TLS Scanner & ApexAdversary Outreach API
	scannerAPI := router.Group("/api/v1/scanner")
	scannerAPI.Use(middleware.JWTAuth(authStore))
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
	{
		auditHandler := handlers.NewAuditHandler(auditLog, logger)
		auditAPI.GET("/logs", auditHandler.ListAuditLogs)
		auditAPI.POST("/logs/query", auditHandler.QueryAuditLogs)
	}

	// Dot1X HTTPS-based AAA API (branch office switches call these endpoints)
	dot1xAPI := router.Group("/api/v1/dot1x")
	dot1xAPI.Use(middleware.GatewayAuth(gwRegistry))
	{
		dot1xHandler := handlers.NewDot1XHandler(dot1xAuth, auditLog, logger)
		dot1xAPI.POST("/authenticate", dot1xHandler.Authenticate)
		dot1xAPI.POST("/authorize", dot1xHandler.Authorize)
		dot1xAPI.POST("/accounting", dot1xHandler.Accounting)
		dot1xAPI.GET("/sessions", dot1xHandler.ListSessions)
		dot1xAPI.GET("/sessions/:id", dot1xHandler.GetSession)
		dot1xAPI.POST("/sessions/:id/disconnect", dot1xHandler.DisconnectSession)
		dot1xAPI.POST("/mac/register", dot1xHandler.RegisterMAC)
		dot1xAPI.DELETE("/mac/:mac", dot1xHandler.RemoveMAC)
		dot1xAPI.GET("/mac", dot1xHandler.ListMACs)
	}

	// Advanced Security Group Tags (SGT) & Branch Sites API
	sgtAPI := router.Group("/api/v1/sgt")
	sgtAPI.Use(middleware.JWTAuth(authStore))
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
	{
		idHandler := handlers.NewIdentityBrokerHandler(idBroker, logger)
		idAPI.GET("/providers", idHandler.ListIdPs)
		idAPI.GET("/providers/:id", idHandler.GetIdP)
		idAPI.POST("/providers", idHandler.CreateIdP)
		idAPI.PUT("/providers/:id", idHandler.UpdateIdP)
		idAPI.DELETE("/providers/:id", idHandler.DeleteIdP)
		idAPI.POST("/token/exchange", idHandler.ExchangeToken)
		idAPI.GET("/sessions", idHandler.ListSessions)
		idAPI.GET("/sessions/:id", idHandler.GetSession)
		idAPI.DELETE("/sessions/:id", idHandler.RevokeSession)
	}

	// Feature Licensing API
	featureAPI := router.Group("/api/v1/features")
	featureAPI.Use(middleware.JWTAuth(authStore))
	{
		featHandler := handlers.NewFeatureHandler(featureStore, orgPlan, logger)
		featureAPI.GET("", featHandler.ListFeatures)
		featureAPI.GET("/:id", featHandler.GetFeature)
		featureAPI.PUT("/:id/toggle", featHandler.ToggleFeature)
		featureAPI.POST("/:id/trial", featHandler.StartTrial)
	}

	// Security Profiles API
	profileAPI := router.Group("/api/v1/profiles")
	profileAPI.Use(middleware.JWTAuth(authStore))
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
	{
		ghostHandler := handlers.NewGhostedAppsHandler(logger)
		ghostAPI.GET("", ghostHandler.ListAgents)
		ghostAPI.GET("/:id", ghostHandler.GetAgent)
		ghostAPI.POST("/rescan", ghostHandler.Rescan)
		ghostAPI.GET("/scan/last", ghostHandler.GetLastScan)
	}

	// Client Config & Route Policy per Group API
	clientConfigHandler := handlers.NewClientConfigHandler(logger)
	ccAPI := router.Group("/api/v1/client-config")
	ccAPI.Use(middleware.JWTAuth(authStore))
	{
		ccAPI.GET("", clientConfigHandler.ListClientConfigs)
		ccAPI.GET("/:group_id", clientConfigHandler.GetClientConfig)
		ccAPI.POST("", clientConfigHandler.CreateClientConfig)
		ccAPI.PUT("/:group_id", clientConfigHandler.UpdateClientConfig)
	}
	routeAPI := router.Group("/api/v1/route-config")
	routeAPI.Use(middleware.JWTAuth(authStore))
	{
		routeAPI.GET("", clientConfigHandler.ListRouteConfigs)
		routeAPI.GET("/:group_id", clientConfigHandler.GetRouteConfig)
		routeAPI.PUT("/:group_id", clientConfigHandler.UpdateRouteConfig)
	}

	// Security Validation API (container-based test infrastructure)
	validationAPI := router.Group("/api/v1/validation")
	validationAPI.Use(middleware.JWTAuth(authStore))
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
	{
		secHandler := handlers.NewSecurityHandler(codeSigningSvc, enrollmentSvc, commandSigningSvc, logger)

		// Code signing
		securityAPI.POST("/sign", secHandler.SignArtifact)
		securityAPI.POST("/verify", secHandler.VerifyArtifact)
		securityAPI.GET("/artifacts", secHandler.ListArtifacts)
		securityAPI.GET("/keys", secHandler.ListSigningKeys)
		securityAPI.GET("/keys/:id", secHandler.GetPublicKey)

		// Enrollment tokens
		securityAPI.POST("/enrollment/tokens", secHandler.CreateEnrollmentToken)
		securityAPI.GET("/enrollment/tokens", secHandler.ListEnrollmentTokens)
		securityAPI.DELETE("/enrollment/tokens/:id", secHandler.RevokeEnrollmentToken)
		securityAPI.POST("/enrollment/enroll", secHandler.EnrollAgent)
		securityAPI.GET("/enrollment/agents", secHandler.ListEnrolledAgents)
		securityAPI.DELETE("/enrollment/agents/:id", secHandler.DeactivateAgent)

		// Command signing
		securityAPI.POST("/commands/issue", secHandler.IssueCommand)
		securityAPI.POST("/commands/verify", secHandler.VerifyCommand)
		securityAPI.GET("/commands", secHandler.ListCommands)
		securityAPI.GET("/commands/pending/:targetId", secHandler.GetPendingCommands)
	}

	// ── Start mTLS server for gateway-to-mgmt-plane communication ──
	// Skipped in demo/cloud mode — Railway only exposes one port.
	// Gateways authenticate via GATEWAY_API_KEY over the shared gRPC+HTTP port.
	// Enable in production by setting MTLS_ENABLED=true with a dedicated port.
	if os.Getenv("MTLS_ENABLED") == "true" {
		go startMTLSServer(ctx, ca, gwRegistry, policyStore, meshCoordinator, wsHub, logger)
		logger.Info("mTLS server enabled", zap.String("addr", envOrDefault("MTLS_LISTEN_ADDR", ":9443")))
	} else {
		logger.Info("mTLS server disabled (set MTLS_ENABLED=true to enable)")
	}

	// ── Multiplex gRPC + HTTP on a single port (Railway only exposes one port) ──
	// gRPC requests carry "Content-Type: application/grpc" — cmux routes them
	// to the gRPC server; everything else goes to the Gin HTTP handler.
	listenAddr := envOrDefault("LISTEN_ADDR", ":8080")
	deployMode := envOrDefault("DEPLOY_MODE", "cloud")

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

	// gRPC server
	grpcSrv := grpcserver.NewServer(grpcserver.Config{
		DevMode: deployMode == "dev",
	}, grpcserver.Deps{
		PolicyStore: policyStore,
		Registry:    gwRegistry,
		Logger:      logger,
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
		if err := mux.Serve(); err != nil {
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
	mtlsAddr := envOrDefault("MTLS_LISTEN_ADDR", ":9443")
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
