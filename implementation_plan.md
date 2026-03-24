# Implementation Plan

This document tracks the current implementation status and the next recommended work items for the repository, with an emphasis on the recent build-system and Python-binding work.

## Status Legend

- `[x]` completed
- `[~]` in progress / partially implemented
- `[ ]` planned

## 1. Build and Tooling

- `[x]` Document Visual Studio and command-line MSBuild workflows in both README files.
- `[x]` Clarify that building the full solution also pulls in the WDK / KMDF kernel projects.
- `[x]` Add platform toolset override properties for user-mode and kernel-mode `.vcxproj` files.
- `[x]` Add root-level `CMakeLists.txt` for Windows user-mode builds.
- `[x]` Support building the static library, example program, and test executable through CMake.
- `[x]` Support building a shared library (`cpueaxh_shared.dll`) for FFI / Python usage through CMake.
- `[x]` Extend `.gitignore` to cover CMake and Python generated artifacts.
- `[ ]` Add CI coverage for MSBuild and CMake user-mode builds.
- `[ ]` Add install/export polish for CMake consumers beyond the current basic target export.

## 2. Python Package

### 2.1 Packaging and Layout

- `[x]` Create an installable Python package under `python/`.
- `[x]` Add `pyproject.toml` for editable installs.
- `[x]` Split the Python glue into package modules (`_bindings`, `_constants`, `_loader`, `engine`, `types`, `errors`).
- `[x]` Add runnable Python examples under `python/src/cpueaxh/examples/`.
- `[x]` Document package install and example usage in the root README files and `python/README.md`.
- `[x]` Add centralized package versioning through `cpueaxh.__version__`.
- `[x]` Keep the long-term Python binding baseline `ctypes`-based unless a concrete limitation appears.

### 2.2 Implemented Python API Surface

- `[x]` DLL discovery with default build-output probing and `CPUEAXH_DLL_PATH` override.
- `[x]` Engine lifecycle:
  - `cpueaxh.Engine`
  - `close()`
  - context-manager support
- `[x]` Memory mode:
  - `set_memory_mode()`
- `[x]` Guest memory helpers:
  - `map_memory()`
  - `unmap_memory()`
  - `protect_memory()`
  - `set_memory_cpu_attrs()`
  - `read_memory()`
  - `write_memory()`
  - `memory_regions()`
- `[x]` Higher-level convenience helpers:
  - `load_code()` with automatic page-aligned mapping
  - `map_host_buffer()`
- `[x]` Register and context access:
  - `write_register_u64()`
  - `read_register_u64()`
  - `read_context()`
  - `write_context()`
  - `set_processor_id()`
- `[x]` Execution control:
  - `start()`
  - `start_function()`
  - `stop()`
- `[x]` Exception query:
  - `code_exception()`
  - `error_code_exception()`
- `[x]` Memory patch helpers:
  - `add_memory_patch()`
  - `delete_memory_patch()`
- `[x]` Hook helpers:
  - `add_code_hook()`
  - `add_code_hook_address()`
  - `add_memory_hook()`
  - `add_invalid_memory_hook()`
  - `delete_hook()`
- `[x]` Backward-compatible aliases for the earlier minimal API names.

### 2.3 Python Examples and Validation

- `[x]` Add a minimal guest-mode demo that loads `mov rax, 42` and prints the result.
- `[x]` Add a code-hook demo that traces instruction addresses and verifies execution result.
- `[x]` Add Python smoke tests for:
  - guest execution
  - code hooks
  - host-buffer mapping
  - processor-id propagation
- `[x]` Add smoke tests for:
  - memory patches
  - invalid memory hooks with retry / recovery
  - context round-trip of richer structures
  - `start_function()` semantics
- `[x]` Add negative-path tests for common error codes and argument validation.

### 2.4 Python API Gaps

- `[x]` Wrap escape registration APIs (`cpueaxh_escape_add()` / `cpueaxh_escape_del()`).
- `[ ]` Evaluate Python support for host-call / native bridge scenarios.
- `[ ]` Add richer typed wrappers for additional register classes and exception enums.
- `[ ]` Improve user-data / callback ergonomics beyond the current closure-based hook helpers.
- `[ ]` Consider a more explicit page / mapping helper layer for Python-side ergonomics.

## 3. Kernel-Mode Support

### 3.1 Current State

- `[x]` Provide a kernel-mode static library project in `kcpueaxh/`.
- `[x]` Reuse the shared emulator core (`cpueaxh.cpp`) for kernel-mode builds via platform abstraction.
- `[x]` Provide a KMDF non-PnP driver sample in `kexample/`.
- `[x]` Build kernel-mode targets with `WindowsKernelModeDriver10.0` by default.
- `[x]` Support overriding the kernel platform toolset through MSBuild properties.
- `[x]` Document that kernel-mode builds require WDK / KMDF.

### 3.2 Recommended Next Kernel Work

- `[ ]` Expand the kernel README / docs with a concrete build + load + debug workflow.
- `[ ]` Document expected target OS / WDK versions and signing assumptions.
- `[ ]` Add a kernel validation checklist for:
  - build success
  - driver load / unload
  - host-mode sample completion
  - expected `DbgPrintEx` output
- `[ ]` Add a minimal regression strategy for kernel builds, even if full automated execution is not feasible.
- `[ ]` Consider whether a kernel-focused test / harness target should be added outside the current sample driver.

## 4. Documentation

- `[x]` Document command-line build instructions in English and Chinese.
- `[x]` Document CMake usage in English and Chinese.
- `[x]` Document the Python package and demo workflow in English and Chinese.
- `[ ]` Add a dedicated Python usage guide with a few realistic guest-mode examples.
- `[ ]` Add a dedicated kernel usage guide.
- `[ ]` Add an integration guide for embedding `cpueaxh` from external C/C++ or CMake-based projects.

## 5. Recommended Work Order

The most practical next steps are:

1. `[ ]` Add CI for user-mode CMake + Python smoke tests.
2. `[ ]` Evaluate whether Python should expose a limited host-call bridge helper, or explicitly stay at software escape emulation only.
3. `[ ]` Write a dedicated kernel build/debug guide.
4. `[ ]` Add a lightweight release checklist once Python package publishing becomes a real distribution need.
5. `[ ]` Expand Python examples into more realistic guest-mode workflows.

## 6. Notes

- The Python layer is now in a good "usable and test-backed" state for guest-mode experimentation and basic hook workflows, but it should still be treated as an evolving binding rather than a complete, frozen API.
- The kernel-mode portion is present and functional at the project/sample level, but it is much less validated and documented than the user-mode and Python paths.
