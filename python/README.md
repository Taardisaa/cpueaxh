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
```

Smoke tests:

```powershell
python -m unittest discover -s python\tests -v
```

Useful high-level helpers on `cpueaxh.Engine`:
- `load_code()`
- `map_host_buffer()`
- `add_code_hook()`
- `add_memory_hook()`
- `add_invalid_memory_hook()`
- `add_memory_patch()`
