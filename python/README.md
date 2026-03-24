# cpueaxh Python Glue

This package provides a small `ctypes`-based wrapper around `cpueaxh_shared.dll`.
The package version is exported as `cpueaxh.__version__` and used as the single source of truth for packaging metadata.

Typical workflow:

```powershell
cmake -S .. -B ..\build -G "Visual Studio 18 2026" -A x64 -T v145 -DCPUEAXH_BUILD_SHARED=ON
cmake --build ..\build --config Debug --target cpueaxh_shared
python -m pip install -e .
python -m cpueaxh.examples.guest_demo
```

Additional examples:

```powershell
python -m cpueaxh.examples.hook_demo
python -m cpueaxh.examples.cpuid_escape_demo
```

Smoke tests:

```powershell
python -m unittest discover -s python\tests -v
```

The current smoke suite covers guest execution, code hooks, escape callbacks, host-buffer mapping, memory patches, invalid-memory recovery, context round-tripping, `start_function()` behavior, and a couple of negative-path error cases.

Useful high-level helpers on `cpueaxh.Engine`:
- `load_code()`
- `map_host_buffer()`
- `add_code_hook()`
- `add_memory_hook()`
- `add_invalid_memory_hook()`
- `add_escape()`
- `add_memory_patch()`

`add_escape()` is the Python-facing way to intercept instruction classes such as `cpuid` or `rdtsc` and override their behavior in software. The callback receives a mutable `CpueaxhX86Context`; updating its registers changes the emulated result, and returning `None` reports success.
