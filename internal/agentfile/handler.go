// Package agentfile serves agent/installer downloads with version support.
// On ECS Fargate, files are stored in S3 and served via redirect.
package agentfile

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler serves agent binaries and installer files.
type Handler struct {
	s3Bucket string
	s3Region string
	logger   *zap.Logger
}

// NewHandler creates a new agent file handler.
func NewHandler(s3Bucket, s3Region string, logger *zap.Logger) *Handler {
	return &Handler{s3Bucket: s3Bucket, s3Region: s3Region, logger: logger}
}

// FileEntry represents a downloadable file.
type FileEntry struct {
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Size     int64  `json:"size,omitempty"`
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

// HandleDownload redirects to the S3 URL for the requested file.
// Query params: ?version=v0.1.0&file=ApexAegis-Setup.exe
func (h *Handler) HandleDownload(c *gin.Context) {
	version := c.Query("version")
	filename := c.Query("file")

	if version == "" || filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "version and file query params required"})
		return
	}

	// Sanitize
	version = strings.TrimPrefix(version, "/")
	filename = strings.TrimPrefix(filename, "/")

	s3URL := h.s3URL(version, filename)
	c.Redirect(http.StatusTemporaryRedirect, s3URL)
}

// s3URL builds the public S3 URL for a file.
func (h *Handler) s3URL(version, filename string) string {
	return "https://" + h.s3Bucket + ".s3." + h.s3Region + ".amazonaws.com/" + version + "/" + filename
}

// listVersions returns the known versions and files.
// Since we can't list S3 without AWS SDK, we use a known structure.
func (h *Handler) listVersions() []FileEntry {
	// Known files — in production this could be cached or use S3 listing.
	// For now, return the files the Windows developer uploaded.
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
			Path:     "/api/v1/agent/download/" + f.Version + "/" + f.Filename,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Version > entries[j].Version
	})

	return entries
}
