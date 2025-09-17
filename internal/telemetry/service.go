package telemetry

import (
	"context"
	"math"
	"runtime/metrics"
)

type MetricsService struct{}

func NewMetricsService() *MetricsService {
	return &MetricsService{}
}

func (s *MetricsService) GetMetrics(ctx context.Context) (cpuPercent, memoryPercent float64, err error) {
	samples := []metrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/memory/classes/heap/objects:bytes"},
	}
	metrics.Read(samples)

	cpuPercent = math.Round(samples[0].Value.Float64()*100) / 100

	memoryBytes := float64(samples[1].Value.Uint64())
	totalMemory := float64(1 << 30)
	memoryPercent = math.Round((memoryBytes/totalMemory)*100*100) / 100

	return cpuPercent, memoryPercent, nil
}
