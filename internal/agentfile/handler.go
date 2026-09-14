// Package agentfile serves agent/installer downloads with version support.
package agentfile

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler serves agent binaries and installer files.
type Handler struct {
	assetsDir string
	logger    *zap.Logger
}

// NewHandler creates a new agent file handler.
// assetsDir is the path to the directory containing agent binaries
// (e.g. /assets/agent with subdirectories like v0.1.0/).
func NewHandler(assetsDir string, logger *zap.Logger) *Handler {
	return &Handler{assetsDir: assetsDir, logger: logger}
}

// FileEntry represents a downloadable file.
type FileEntry struct {
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Path     string `json:"path"` // download URL path
}

// RegisterRoutes registers the agent file download routes.
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	router.GET("/versions", h.HandleListVersions)
	router.GET("/latest", h.HandleLatest)
	router.GET("/:version/:filename", h.HandleDownload)
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
	// Group files by version, return latest
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

// HandleDownload serves a specific file.
func (h *Handler) HandleDownload(c *gin.Context) {
	version := c.Param("version")
	filename := c.Param("filename")

	// Sanitize path components
	version = filepath.Base(version)
	filename = filepath.Base(filename)

	filePath := filepath.Join(h.assetsDir, version, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	// Set appropriate content type based on extension
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".msi":
		c.Header("Content-Type", "application/x-msi")
	case ".exe":
		c.Header("Content-Type", "application/x-msdownload")
	case ".zip":
		c.Header("Content-Type", "application/zip")
	default:
		c.Header("Content-Type", "application/octet-stream")
	}

	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.File(filePath)
}

// listVersions scans the assets directory and returns version info.
func (h *Handler) listVersions() []FileEntry {
	var entries []FileEntry

	versionsDir := filepath.Join(h.assetsDir)
 dirs, err := os.ReadDir(versionsDir)
	if err != nil {
		h.logger.Warn("failed to read assets directory", zap.String("dir", versionsDir), zap.Error(err))
		return entries
	}

	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		version := dir.Name()
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}

		filesDir := filepath.Join(versionsDir, dir.Name())
		files, err := os.ReadDir(filesDir)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			info, err := file.Info()
			if err != nil {
				continue
			}
			entries = append(entries, FileEntry{
				Version:  version,
				Filename: file.Name(),
				Size:     info.Size(),
				Path:     "/api/v1/agent/download/" + version + "/" + file.Name(),
			})
		}
	}

	// Sort by version descending (latest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Version > entries[j].Version
	})

	return entries
}

// VersionInfo is the JSON response for /api/v1/agent/download/versions.
type VersionInfo struct {
	Versions []FileEntry `json:"versions"`
}

func init() {
	// Ensure json is used
	_ = json.Marshal
}
