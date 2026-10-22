#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dp::tests
{

struct StressUnit {
    std::uint64_t idx;
    std::vector<std::uint8_t> bytes;
};

struct StressConfig
{
    std::uint64_t packet_count = 1000000; // by default, 1 million packets
    std::size_t queue_capacity = 1024; // default queue capacity of 1024 packets
    bool print_metrics = true;
};

struct StressResult
{
    bool passed = false;

    std::uint64_t packets_generated = 0;
    std::uint64_t packets_enqueued = 0;
    std::uint64_t packets_processed = 0;

    std::uint64_t bytes_processed = 0;

    std::uint64_t validation_failures = 0;
    std::uint64_t queue_full_events = 0;

    double elapsed_seconds = 0.0;

    double packets_per_second = 0.0;
    double bytes_per_second = 0.0;
};

StressResult run_pipeline_stress_test(
    const StressConfig& config = {}
);

} // namespace dp::tests