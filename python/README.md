# cpueaxh Python Glue

This package provides a small `ctypes`-based wrapper around `cpueaxh_shared.dll`.

Typical workflow:

```powershell
cmake -S .. -B ..\build -G "Visual Studio 18 2026" -A x64 -T v145 -DCPUEAXH_BUILD_SHARED=ON
cmake --build ..\build --config Debug --target cpueaxh_shared
python -m pip install -e .
python -m cpueaxh.examples.guest_demo
```
