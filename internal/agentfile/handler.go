// Package agentfile serves agent/installer downloads with version support.
// On ECS Fargate, files are stored in S3 and proxied through the management plane.
package agentfile

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler serves agent binaries and installer files.
type Handler struct {
	s3Client *s3.Client
	s3Bucket string
	s3Region string
	logger   *zap.Logger
}

// NewHandler creates a new agent file handler.
func NewHandler(s3Bucket, s3Region string, logger *zap.Logger) *Handler {
	return &Handler{
		s3Bucket: s3Bucket,
		s3Region: s3Region,
		logger:   logger,
	}
}

// initS3Client lazily initializes the S3 client on first use.
func (h *Handler) initS3Client(ctx context.Context) error {
	if h.s3Client != nil {
		return nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(h.s3Region))
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	h.s3Client = s3.NewFromConfig(cfg)
	return nil
}

// FileEntry represents a downloadable file.
type FileEntry struct {
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
}

// RegisterRoutes registers the agent file download routes.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	router.GET("/versions", h.HandleListVersions)
	router.GET("/latest", h.HandleLatest)
	router.GET("/file", h.HandleDownload)
}

// HandleListVersions returns all available versions and their files.
func (h *Handler) HandleListVersions(c *gin.Context) {
	versions := h.listVersions()
	c.JSON(http.StatusOK, gin.H{"versions": versions})
}

// HandleLatest returns the latest version's files.
func (h *Handler) HandleLatest(c *gin.Context) {
	versions := h.listVersions()
	if len(versions) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no files available"})
		return
	}
	latestVersion := versions[0].Version
	var files []FileEntry
	for _, v := range versions {
		if v.Version == latestVersion {
			files = append(files, v)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"version": latestVersion,
		"files":   files,
	})
}

// HandleDownload proxies the file from S3 to the client.
// Query params: ?version=v0.1.0&file=ApexAegis-Setup.exe
func (h *Handler) HandleDownload(c *gin.Context) {
	version := c.Query("version")
	filename := c.Query("file")

	if version == "" || filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "version and file query params required"})
		return
	}

	version = strings.TrimPrefix(version, "/")
	filename = strings.TrimPrefix(filename, "/")

	// Initialize S3 client on first request
	if err := h.initS3Client(c.Request.Context()); err != nil {
		h.logger.Error("failed to initialize S3 client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "storage not available"})
		return
	}

	s3Key := version + "/" + filename

	result, err := h.s3Client.GetObject(c.Request.Context(), &s3.GetObjectInput{
		Bucket: aws.String(h.s3Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		h.logger.Error("failed to get object from S3",
			zap.String("bucket", h.s3Bucket),
			zap.String("key", s3Key),
			zap.Error(err),
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	defer result.Body.Close()

	ext := strings.ToLower(filename[strings.LastIndex(filename, "."):])
	switch ext {
	case ".msi":
		c.Header("Content-Type", "application/x-msi")
	case ".exe":
		c.Header("Content-Type", "application/x-msdownload")
	default:
		c.Header("Content-Type", "application/octet-stream")
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	if result.ContentLength != nil {
		c.Header("Content-Length", fmt.Sprintf("%d", *result.ContentLength))
	}

	c.Status(http.StatusOK)
	if _, err := io.Copy(c.Writer, result.Body); err != nil {
		h.logger.Error("failed to stream file to client", zap.Error(err))
	}
}

// listVersions returns the known versions and files.
func (h *Handler) listVersions() []FileEntry {
	var entries []FileEntry

	knownFiles := []struct {
		Version  string
		Filename string
	}{
		{"v0.1.0", "ApexAegis-Setup.exe"},
	}

	for _, f := range knownFiles {
		entries = append(entries, FileEntry{
			Version:  f.Version,
			Filename: f.Filename,
			Path:     "/api/v1/agent/download/file?version=" + f.Version + "&file=" + f.Filename,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Version > entries[j].Version
	})

	return entries
}
