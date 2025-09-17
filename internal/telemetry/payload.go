package telemetry

// @Description Health check response with CPU and memory usage
type HealthResponse struct {
	CPUUsagePercent   float64 `json:"cpu_usage_percent"`
	MemoryUsedPercent float64 `json:"memory_used_percent"`
}
