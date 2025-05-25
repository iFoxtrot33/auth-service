package telemetry

import (
	"math"
	"net/http"

	"AuthService/pkg/res"

	"github.com/rs/zerolog"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type HealthHandler struct {
	Logger zerolog.Logger
}

func NewHealthHandler(router *http.ServeMux, logger zerolog.Logger) {
	handler := &HealthHandler{Logger: logger}
	router.HandleFunc("GET /api/v1/health", handler.handleHealth())
}

// handleHealth возвращает текущий расход CPU и памяти
// @Summary Health check
// @Description Returns current CPU and memory usage percentages
// @Tags telemetry
// @Produce json
// @Success 200 {object} HealthResponse "CPU and memory usage"
// @Failure 500 {object} map[string]string "Failed to get CPU or memory usage"
// @Router /api/v1/health [get]
func (h *HealthHandler) handleHealth() http.HandlerFunc {
	tracer := otel.Tracer("auth-service")

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "handleHealth")
		defer span.End()

		cpuPercent, err := cpu.PercentWithContext(ctx, 0, false)
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to get CPU usage")
			span.RecordError(err)
			span.SetAttributes(attribute.String("error", "failed to get CPU usage"))
			res.Json(w, map[string]string{"error": "Failed to get CPU usage"}, http.StatusInternalServerError)
			return
		}
		var cpuUsage float64
		if len(cpuPercent) > 0 {
			cpuUsage = math.Round(cpuPercent[0]*100) / 100
			span.SetAttributes(attribute.Float64("cpu_usage_percent", cpuUsage))
		}

		vm, err := mem.VirtualMemoryWithContext(ctx)
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to get memory usage")
			span.RecordError(err)
			span.SetAttributes(attribute.String("error", "failed to get memory usage"))
			res.Json(w, map[string]string{"error": "Failed to get memory usage"}, http.StatusInternalServerError)
			return
		}

		memoryUsedPercent := math.Round(vm.UsedPercent*100) / 100
		span.SetAttributes(attribute.Float64("memory_used_percent", memoryUsedPercent))

		response := HealthResponse{
			CPUUsagePercent:   cpuUsage,
			MemoryUsedPercent: memoryUsedPercent,
		}

		h.Logger.Info().
			Float64("cpu_usage_percent", cpuUsage).
			Float64("memory_used_percent", memoryUsedPercent).
			Msg("Health check requested")

		res.Json(w, response, http.StatusOK)
	}
}
