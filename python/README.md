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
python -m cpueaxh.examples.ntreadfile_demo
python -m cpueaxh.examples.ntreadfile_shellcode_demo
```

Smoke tests:

```powershell
python -m unittest discover -s python\tests -v
```

The current smoke suite covers guest execution, code hooks, escape callbacks, native bridge callbacks, a host `NtReadFile` syscall demo path, a direct-`syscall` shellcode demo path, host-buffer mapping, memory patches, invalid-memory recovery, context round-tripping, `start_function()` behavior, and a couple of negative-path error cases.

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

That separation matters most for syscall-oriented shellcode. A practical pattern is:

1. prepare host-accessible buffers and stack pages from Python,
2. let the emulated shellcode arrange registers, stack arguments, and the raw `syscall` instruction itself,
3. attach a generic `CPUEAXH_ESCAPE_INSN_SYSCALL` callback that just forwards to `host_call(..., cpueaxh_example_execute_syscall)`.

In other words, the Python side stays lightweight glue while the shellcode controls the actual syscall payload.

For that workflow, the package now also provides reusable helpers:

- `cpueaxh.HostPage`
- `cpueaxh.NativeBridgeLibrary`
- `cpueaxh.HostBridgeSession`
- `cpueaxh.WindowsSyscallBufferSpec`
- `cpueaxh.WindowsSyscallSpec`
- `cpueaxh.WindowsSyscallResult`

`HostBridgeSession` wraps the repetitive host-mode setup for native bridge experiments:

- page-aligned host allocation through `VirtualAlloc`
- host-buffer mapping into the engine
- host stack setup
- instruction-pointer setup for loaded code
- a convenience `add_host_call_escape()` helper
- Windows x64 argument setup through `set_windows_x64_arguments()`
- reusable native syscall execution through `invoke_windows_syscall()`
- call-spec based syscall execution through `invoke_windows_syscall_spec()`

Those syscall helpers are convenience APIs for tests and small experiments. They are useful when you want Python to drive a host syscall directly, but they are not the core design goal of the binding.

The current `host_call_demo` uses this helper layer to exercise both native `cpuid` and native `xgetbv` bridge stubs without manual page bookkeeping. `ntreadfile_demo` shows the convenience path where Python prepares and invokes a Windows `NtReadFile` call. `ntreadfile_shellcode_demo` shows the more emulator-centric path, which is closer to the intended model for syscall-heavy shellcode: the shellcode emits a raw `syscall`, and Python only supplies the generic escape bridge and host-mode setup.
