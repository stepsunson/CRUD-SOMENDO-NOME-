if(ENABLE_LLVM_SHARED)
set(llvm_libs "LLVM")
else()
set(llvm_raw_libs bitwriter bpfcodegen debuginfodwarf irreader linker
  mcjit objcarcopts option passes lto)
if(ENABLE_LLVM_NATIVECODEGEN)
set(llvm_raw_libs ${llvm_raw_libs} nativecodegen)
endif()
list(FIND LLVM_AVAILABLE_LIBS "LLVMCoverage" _llvm_coverage)
if (${_llvm_coverage} GREATER -1)
  list(APPEND llvm_raw_libs coverage)
endif()
list(FIND LLVM_AVAILABLE_LIBS "LLVMCoroutines" _llvm_coroutines)
if (${_llvm_coroutines} GREATER -1)
  list(APPEND llvm_raw_libs coroutines)
endif()
list(FIND LLVM_AVAILABLE_LIBS "LLVMFrontendOpenMP" _llvm_frontendOpenMP)
if (${_llvm_frontendOpenMP} GREATER -1)
  list(APPEND llvm_raw_libs frontendopenmp)
endif()
if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 6 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 6)
  list(APPEND llvm_raw_libs bpfasmparser)
  list(APPEND llvm_raw_libs bpfdisassembler)
endif()
if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 15 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 15)
  list(APPEND llvm_raw_libs windowsdriver)
endif()
if (${LLVM_PACKAGE_VERSION} VERSION_EQUAL 16 OR ${LLVM_PACKAGE_VERSION} VERSION_GREATER 16)
  list(APPEND llvm_raw_libs frontendhlsl)
endif()

llvm_map_components_to_libnames(_llvm_libs ${llvm_raw_libs})
llvm_expand_dependencies(llvm_libs ${_llvm_libs})
endif()

if(ENABLE_LLVM_SHARED AND NOT libclang-shared STREQUAL "libclang-shared-NOTFOUND")
set(clang_libs ${libclang-shared})
else()
# order is important
set(clang_libs
  ${libclangFrontend}
  ${libclangSerialization}
  ${lib