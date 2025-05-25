package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthHandler(t *testing.T) {
	logger := zerolog.Nop()
	mux := http.NewServeMux()
	NewHealthHandler(mux, logger)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, response.CPUUsagePercent, 0.0)
	assert.LessOrEqual(t, response.CPUUsagePercent, 100.0)
	assert.GreaterOrEqual(t, response.MemoryUsedPercent, 0.0)
	assert.LessOrEqual(t, response.MemoryUsedPercent, 100.0)
}

func TestHealthHandlerMethods(t *testing.T) {
	logger := zerolog.Nop()
	mux := http.NewServeMux()
	NewHealthHandler(mux, logger)

	methods := []string{"POST", "PUT", "DELETE"}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/v1/health", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	}
}
