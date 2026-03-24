# Python Host Call / Native Bridge Evaluation

This note explains what `cpueaxh_host_call()` is for, how it relates to escape callbacks, and whether the Python binding should expose it directly.

## Short Version

- An escape callback is the interception point.
- `cpueaxh_host_call()` is an optional implementation strategy inside an escape callback.
- Python can and should wrap that API as glue.
- The actual bridge target still needs to be native code written in `asm` or low-level `C/C++`.
- So the practical model is: Python orchestrates, native code executes the bridge.

In practice:

- `cpuid`, `rdtsc`, `rdtscp`, `xgetbv`, `rdrand` can often be handled entirely in software by editing `CpueaxhX86Context`.
- Python is a good fit for that software-emulation path.
- Python is also a good fit for wiring escape callbacks to a native bridge symbol loaded from a DLL.

## The Building Blocks

The public x86 escape callback type is:

```c
typedef cpueaxh_err (*cpueaxh_cb_escape_t)(
    cpueaxh_engine* engine,
    cpueaxh_x86_context* context,
    const uint8_t* instruction,
    void* user_data);
```

Relevant public APIs:

```c
cpueaxh_err cpueaxh_escape_add(...);
cpueaxh_err cpueaxh_escape_del(...);
cpueaxh_err cpueaxh_host_call(cpueaxh_x86_context* context, cpueaxh_cb_host_bridge_t bridge);
```

See:

- [`cpueaxh.hpp`](/c:/Users/13666/Workspace/cpueaxh/cpueaxh/cpueaxh.hpp)
- [`cpueaxh.cpp`](/c:/Users/13666/Workspace/cpueaxh/cpueaxh/cpueaxh.cpp)
- [`host_bridge.asm`](/c:/Users/13666/Workspace/cpueaxh/cpueaxh/host_bridge.asm)

## Escape vs Host Call

These two concepts are related, but they are not the same thing.

### Escape

An escape is the emulator-level interception mechanism.

When execution reaches a supported instruction class such as `cpuid`, `rdtsc`, `xgetbv`, `syscall`, or `int3`, the engine can:

1. recognize that instruction class,
2. stop normal emulation for that instruction,
3. call the registered escape callback,
4. let the callback decide what the instruction should do.

The callback receives a mutable `cpueaxh_x86_context`. If the callback edits registers in that context, those edits become the emulated result.

That means an escape callback can do pure software emulation, with no native bridge at all.

### Host Call

`cpueaxh_host_call()` is a helper for one specific style of escape implementation:

- take the emulated x86 context,
- load it into real machine state,
- jump into a native bridge routine,
- let that routine execute on the host CPU,
- capture the resulting machine state back into the emulator context.

So:

- escape = the interception point
- host call = one possible implementation of the intercepted instruction

## What `cpueaxh_host_call()` Actually Does

At a high level, `cpueaxh_host_call()` is a controlled context switch between emulated state and real host execution.

The current implementation does roughly this:

1. The engine prepares an internal bridge block and stores its pointer in `context->internal_bridge_block`.
2. The escape callback decides to call `cpueaxh_host_call(context, bridge)`.
3. `cpueaxh_host_call()` validates that the context came from an escape path and forwards to the assembly helper.
4. [`host_bridge.asm`](/c:/Users/13666/Workspace/cpueaxh/cpueaxh/host_bridge.asm) saves the current host register, flag, SIMD, and stack state.
5. The assembly helper loads the emulated register file and flags from `cpueaxh_x86_context`.
6. The guest stack is patched so the top of the stack contains a resume target and bridge metadata.
7. Control jumps into the user-provided native bridge routine.
8. When the bridge routine finishes, it resumes through the prepared return path.
9. The assembly helper captures the resulting register, flag, and SIMD state back into `cpueaxh_x86_context`.
10. The original host state is restored and control returns to the library.

That is much heavier than a normal callback. It is effectively a tiny execution handoff protocol.

One practical consequence is that `context->rsp` must point at valid writable host-accessible memory before `cpueaxh_host_call()` is used. The bridge path writes resume metadata to the top of that stack before transferring control.

## Why Some Escapes Use Host Call and Others Do Not

The example project shows both strategies:

- native bridge path for `syscall`, `cpuid`, and `xgetbv`
- software emulation path for `rdtsc`, `rdtscp`, and `rdrand`

See:

- [`escape.hpp`](/c:/Users/13666/Workspace/cpueaxh/example/demo/escape/escape.hpp)
- [`host.hpp`](/c:/Users/13666/Workspace/cpueaxh/example/demo/examples/host.hpp)

This split makes sense.

### Good candidates for software escape emulation

These instructions often only need a controlled register result:

- `cpuid`
- `rdtsc`
- `rdtscp`
- `xgetbv`
- `rdrand`

For many use cases, it is better to set the result explicitly than to execute the real host instruction:

- you can hide host capabilities,
- you can return deterministic test values,
- you can emulate a target machine rather than expose the real machine,
- you can avoid native-bridge complexity entirely.

This is exactly what the current Python `add_escape()` API now supports well.

### Better candidates for native bridge

The host-call path is more interesting when the instruction or behavior is tightly coupled to real machine execution, calling convention details, or an existing native code path.

Examples:

- `syscall` / `sysenter`
- more complex host-integrated escape behaviors
- highly specialized experiments that already depend on handwritten bridge code

## What Python Should Do Here

Python can register an escape callback just fine, and Python can also wrap `cpueaxh_host_call()` just fine.

The important distinction is this:

- Python is a good orchestration layer for host-call usage.
- Python is not the bridge routine itself.

### 1. The bridge is native control flow, not a normal callback

The bridge routine is entered through a low-level stack and register handoff. It is not just "call a function pointer with some arguments".

That means the bridge needs to obey native calling and resume conventions very precisely.

### 2. The current bridge is assembly-backed and ABI-sensitive

The implementation in [`host_bridge.asm`](/c:/Users/13666/Workspace/cpueaxh/cpueaxh/host_bridge.asm) is tightly coupled to:

- Windows x64 calling conventions
- the current context layout
- register save/restore rules
- stack patching assumptions

Python `ctypes` callbacks are not a replacement for that kind of bridge routine.

### 3. It is usually unnecessary for the bridge body to be Python

For the instruction classes most attractive to Python users, software escape emulation is often already enough.

If a Python user wants to control `cpuid` or `rdtsc`, the most natural API is:

1. intercept that instruction class,
2. inspect the emulated register inputs,
3. write the output registers,
4. return success.

That is simple, deterministic, and testable.

## Recommended Python Position

The recommended boundary for the Python package is:

- support escape registration,
- support `cpueaxh_host_call()` as a wrapped glue API,
- support software emulation by mutating `CpueaxhX86Context`,
- treat the bridge target as native code supplied by the user or by helper DLLs.

In other words:

- Python should be good at "decide what this instruction returns".
- Python should also be good at "choose which native bridge symbol to forward into".
- Native bridge code itself should remain a `C/C++/asm` concern.

## What Could Be Exposed Later

If there is future demand, there are safer incremental options than "Python host-call support".

### Option 1: helper recipes, not host-call wrappers

Add higher-level Python helpers for common escapes:

- `add_cpuid_escape(handler)`
- `add_rdtsc_escape(handler)`
- `add_xgetbv_escape(handler)`

These would stay fully in software and simply manipulate the context.

This repository now also has a complementary host-oriented helper layer:

- `HostPage`
- `NativeBridgeLibrary`
- `HostBridgeSession`

That layer is intentionally pragmatic. It does not hide the distinction between software escapes and native bridge escapes, but it does hide the repetitive page-allocation, stack-setup, and DLL-loading work needed for the native path.

### Option 2: document mixed-language integration

If someone needs native bridge behavior with Python in the same project, the clean design is:

- keep the bridge implementation in native code,
- expose a smaller native-facing policy surface,
- let Python configure or select behavior,
- do not make Python itself the bridge routine.

### Option 3: explicitly expose a "not supported" boundary

It is also valid to make this explicit in the docs:

- escape callbacks are supported in Python,
- native bridge callbacks are not a supported Python scenario.

That would reduce confusion and keep the binding honest.

## Suggested Next Step

For the Python binding, the most valuable next work is not direct host-call support. It is one of these:

1. add richer helper APIs around software escapes,
2. improve callback ergonomics,
3. add CI coverage for the Python smoke suite,
4. add more examples for realistic `cpuid` / `rdtsc` customization patterns.

## Practical Conclusion

`cpueaxh_host_call()` is a native bridge tool for escape callbacks, not a general-purpose "run host code from Python" API.

For Python:

- escape support is useful,
- software emulation is the right default when it is enough,
- host-call wrapping is still valuable,
- the bridge target should stay native while Python acts as glue around it.
