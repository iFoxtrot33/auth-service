package telemetry

import (
	"net/http"

	"AuthService/pkg/res"

	"github.com/rs/zerolog"
	otelhttp "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
)

type HealthHandler struct {
	Logger  zerolog.Logger
	Service *MetricsService
}

func NewHealthHandler(router *http.ServeMux, logger zerolog.Logger, service *MetricsService) error {

	if err := otelruntime.Start(otelruntime.WithMeterProvider(otel.GetMeterProvider())); err != nil {
		logger.Error().Err(err).Msg("Failed to start runtime instrumentation")
		return err
	}

	handler := &HealthHandler{Logger: logger, Service: service}
	router.Handle("/api/v1/health", otelhttp.NewHandler(
		http.HandlerFunc(handler.handleHealth()),
		"health_check",
	))

	return nil
}

func (h *HealthHandler) handleHealth() http.HandlerFunc {
	tracer := otel.Tracer("auth-service")

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), "handleHealth")
		defer span.End()

		cpuPercent, memoryPercent, err := h.Service.GetMetrics(ctx)
		if err != nil {
			h.Logger.Error().Err(err).Msg("Failed to get metrics")
			span.RecordError(err)
			res.Json(w, map[string]string{"error": "Failed to get metrics"}, http.StatusInternalServerError)
			return
		}

		response := HealthResponse{
			CPUUsagePercent:   cpuPercent,
			MemoryUsedPercent: memoryPercent,
		}

		h.Logger.Info().
			Float64("cpu_usage_percent", cpuPercent).
			Float64("memory_used_percent", memoryPercent).
			Msg("Health check requested")

		res.Json(w, response, http.StatusOK)
	}
}
