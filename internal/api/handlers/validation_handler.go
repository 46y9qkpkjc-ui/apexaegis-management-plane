package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/validation"
)

// ValidationHandler handles security validation API requests.
type ValidationHandler struct {
	engine *validation.Engine
	logger *zap.Logger
}

// NewValidationHandler creates a new handler.
func NewValidationHandler(engine *validation.Engine, logger *zap.Logger) *ValidationHandler {
	return &ValidationHandler{engine: engine, logger: logger}
}

// ListTests returns all available test categories and their test cases.
func (h *ValidationHandler) ListTests(c *gin.Context) {
	cats := validation.DefaultTestCategories()
	c.JSON(http.StatusOK, gin.H{"categories": cats})
}

// ProvisionEnvironment creates the ephemeral container test infrastructure.
func (h *ValidationHandler) ProvisionEnvironment(c *gin.Context) {
	var req struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.TTLSeconds = 900
	}

	env, err := h.engine.ProvisionEnvironment(context.Background(), req.TTLSeconds)
	if err != nil {
		h.logger.Error("Failed to provision environment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision test environment"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"environment": env,
		"message":     "Test environment provisioning started",
	})
}

// GetEnvironmentStatus returns the current status of a test environment.
func (h *ValidationHandler) GetEnvironmentStatus(c *gin.Context) {
	envID := c.Param("id")
	env, ok := h.engine.GetEnvironment(envID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "environment not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"environment": env})
}

// DestroyEnvironment tears down the ephemeral test infrastructure.
func (h *ValidationHandler) DestroyEnvironment(c *gin.Context) {
	envID := c.Param("id")
	if err := h.engine.DestroyEnvironment(envID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Environment destroyed"})
}

// RunTests executes a test run against the specified categories.
func (h *ValidationHandler) RunTests(c *gin.Context) {
	envID := c.Param("id")

	var req validation.TestRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "categories required"})
		return
	}

	result, err := h.engine.RunTests(envID, req.Categories)
	if err != nil {
		h.logger.Error("Test run failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}

// GetRunResult returns the result of a test run.
func (h *ValidationHandler) GetRunResult(c *gin.Context) {
	runID := c.Param("runId")
	run, ok := h.engine.GetRun(runID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": run})
}

// ListEnvironments returns all test environments.
func (h *ValidationHandler) ListEnvironments(c *gin.Context) {
	envs := h.engine.ListEnvironments()
	c.JSON(http.StatusOK, gin.H{"environments": envs})
}

// SimulatePolicy performs a dry-run policy evaluation.
func (h *ValidationHandler) SimulatePolicy(c *gin.Context) {
	var req validation.PolicySimulationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid simulation input"})
		return
	}

	result, err := h.engine.SimulatePolicy(req)
	if err != nil {
		h.logger.Error("Policy simulation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "simulation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": result})
}
