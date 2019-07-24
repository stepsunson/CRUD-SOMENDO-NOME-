#include "usdt_sample_lib1/lib1.h"

// std
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

// usdt_sample_lib1
#include "folly/tracing/StaticTracepoint.h"

// When using systemtap-sdt-devel, the following file should be included:
#include "lib1_sdt.h"

OperationRequest::OperationRequest(const