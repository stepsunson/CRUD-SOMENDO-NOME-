/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include "PyPerfType.h"

namespace ebpf {
namespace pyperf {

extern const OffsetConfig kPy36OffsetConfig = {
    .PyObject_type = 8,               // offsetof(PyObject, ob_type)
   