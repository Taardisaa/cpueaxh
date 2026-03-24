# cpueaxh Python Glue

This package provides a small `ctypes`-based wrapper around `cpueaxh_shared.dll`.
The package version is exported as `cpueaxh.__version__` and used as the single source of truth for packaging metadata.

Typical workflow:

```powershell
cmake -S .. -B ..\build -G "Visual Studio 18 2026" -A x64 -T v145 -DCPUEAXH_BUILD_SHARED=ON -DCPUEAXH_BUILD_NATIVE_BRIDGES=ON
cmake --build ..\build --config Debug --target cpueaxh_shared cpueaxh_native_bridges
python -m pip install -e .
python -m cpueaxh.examples.guest_demo
```

Additional examples:

```powershell
python -m cpueaxh.examples.hook_demo
python -m cpueaxh.examples.cpuid_escape_demo
python -m cpueaxh.examples.host_call_demo
```

Smoke tests:

```powershell
python -m unittest discover -s python\tests -v
```

The current smoke suite covers guest execution, code hooks, escape callbacks, native bridge callbacks, host-buffer mapping, memory patches, invalid-memory recovery, context round-tripping, `start_function()` behavior, and a couple of negative-path error cases.

Useful high-level helpers on `cpueaxh.Engine`:
- `load_code()`
- `map_host_buffer()`
- `add_code_hook()`
- `add_memory_hook()`
- `add_invalid_memory_hook()`
- `add_escape()`
- `host_call()`
- `add_memory_patch()`

`add_escape()` is the Python-facing way to intercept instruction classes such as `cpuid` or `rdtsc` and override their behavior in software. The callback receives a mutable `CpueaxhX86Context`; updating its registers changes the emulated result, and returning `None` reports success.

`host_call()` is the companion glue API for the native-bridge path. The intended usage is:

1. load a native bridge DLL with `ctypes.WinDLL(...)`,
2. get an exported bridge symbol such as `cpueaxh_example_execute_cpuid`,
3. call `engine.host_call(context, bridge_symbol)` from inside an escape callback.

The bridge symbol itself must still be native code that follows the cpueaxh bridge convention; Python is the orchestration layer, not the bridge implementation. The emulated context also needs a valid host-accessible stack in `RSP`, because the host-call path writes resume metadata to the top of that stack before jumping into the native bridge.

For that workflow, the package now also provides reusable helpers:

- `cpueaxh.HostPage`
- `cpueaxh.NativeBridgeLibrary`
- `cpueaxh.HostBridgeSession`

`HostBridgeSession` wraps the repetitive host-mode setup for native bridge experiments:

- page-aligned host allocation through `VirtualAlloc`
- host-buffer mapping into the engine
- host stack setup
- instruction-pointer setup for loaded code
- a convenience `add_host_call_escape()` helper

The current `host_call_demo` uses this helper layer to exercise both native `cpuid` and native `xgetbv` bridge stubs without manual page bookkeeping.
