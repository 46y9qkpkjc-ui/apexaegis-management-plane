package main

import (
	"fmt"
	"os"

	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL is required")
		os.Exit(1)
	}

	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "internal/db/migrations"
	}

	tenantOrgID := os.Getenv("APP_TENANT_ORG_ID")
	if tenantOrgID == "" {
		tenantOrgID = db.SystemThreatOrgID
	}

	dbConn, err := db.Open(db.Config{DSN: databaseURL, TenantOrgID: tenantOrgID}, logger)
	if err != nil {
		logger.Fatal("failed to connect to database", zap.Error(err))
	}
	defer dbConn.Close()

	if err := dbConn.Migrate(migrationsDir); err != nil {
		logger.Fatal("database migration failed", zap.Error(err))
	}

	logger.Info("database migration completed successfully")
}
