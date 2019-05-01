/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#pragma once

#include "PyPerfSampleProcessor.h"

namespace ebpf {
namespace pyperf {

class PyPerfDefaultPrinter : public PyPerfSampleProcessor {
 public:
  PyPerfDefaultPrinter(bool showGILState, bool showThreadState,
                       bool showPthreadIDState)
   