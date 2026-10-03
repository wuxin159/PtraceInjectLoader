# PtraceInjectLoader

**Ptrace Inject Remote ELF Loader** for Android AArch64.

PtraceInjectLoader is a native command-line loader for placing an ELF64 AArch64 shared object (DSO) into an existing process without asking the target linker to load that shared object through `dlopen`. It uses ordinary Linux `ptrace` operations and remote AArch64 system calls, then performs the ELF image loading work itself inside the target address space.

The input file must be an ELF64 AArch64 `ET_DYN` shared object, conventionally named with a `.so` suffix. It is not started as an independent process through `main`; after loading and relocation, the injector calls a named exported function symbol. The project accepts an explicit PID. The current implementation allocates one anonymous RWX span for the complete ELF image, copies file-backed bytes and zero-fills BSS, resolves standard `DT_NEEDED` libraries through the target's existing linker, applies relocations, and invokes constructors. The injected DSO itself is never passed to `dlopen`; dependency handles are opened only to resolve symbols against libraries already available to the target.

## Build

The project is configured for the Android NDK and `arm64-v8a`:

```powershell
cmake -S . -B cmake-build-debug -G Ninja `
  -DCMAKE_MAKE_PROGRAM="<path-to-ninja>/ninja.exe" `
  -DCMAKE_TOOLCHAIN_FILE="<path-to-android-ndk>/build/cmake/android.toolchain.cmake" `
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26
cmake --build cmake-build-debug --parallel
```

The output executable is `cmake-build-debug/PtraceInjectLoader`.

## Usage

Inspect an ELF shared object without touching a target process:

```sh
/data/local/tmp/PtraceInjectLoader --inspect /data/local/tmp/libexample.so
```

Inject into a selected process as root:

```sh
/data/local/tmp/PtraceInjectLoader \
  --inject --pid 1234 /data/local/tmp/libexample.so \
  --entry module_entry
```

The entry arguments are optional AArch64 integer/pointer values passed to the exported function symbol:

```sh
--arg0 0x1234 --arg1 7
```

The injector records the current SELinux enforcement state. If the device is enforcing, it temporarily invokes `setenforce 0` for the injection window and restores enforcing before exit. It does not change a device that was already permissive.

## Loading model

1. Validate the target PID and confirm that its executable is ELF64 AArch64.
2. Attach all target threads with `ptrace` and preserve their register state.
3. Remote-call `mmap` with `PROT_READ | PROT_WRITE | PROT_EXEC` for the complete image span.
4. Copy the parsed image into target memory and leave BSS and gaps zero-filled.
5. Resolve `DT_NEEDED` libraries and target linker functions through the target's mapped ELF files.
6. Apply RELA, RELR, symbol, IFUNC, PLT and relative relocations.
7. Run `DT_INIT` and `DT_INIT_ARRAY` entries, then call the requested entry symbol.
8. Restore registers, detach all threads, verify the process generation, and restore SELinux state.

Shared objects containing ELF TLS are rejected explicitly because registering a new TLS module in every target thread requires Android linker/runtime integration beyond this loader's contract.

## Supported shared objects and limitations

- Android AArch64 only.
- ELF64 AArch64 `ET_DYN` shared objects (DSOs), conventionally using a `.so` suffix.
- One contiguous zero-filled image covering all `PT_LOAD` segments, including BSS and inter-segment gaps.
- `DT_NEEDED` dependencies that are already available in the target Android linker namespace.
- RELA, compressed RELR, AArch64 absolute and PC-relative relocations, PLT, GLOB_DAT, RELATIVE, IRELATIVE, and GNU IFUNC.
- `DT_INIT` and `DT_INIT_ARRAY` execution.
- A named `STT_FUNC` or `STT_GNU_IFUNC` entry point.

The loader does not register ELF TLS modules, unload the image, run finalizers after a successful entry call, integrate C++ exception domains, create linker namespaces, or replace the Android linker. RWX allocation is intentional. The current SELinux enforcement state is saved before injection and restored after normal completion or failure cleanup.

The executable must run as root. The caller is responsible for choosing a valid target PID and a shared object that is appropriate for that process. The requested entry must be an exported function symbol in the shared object; it is not the process `main` entry point.

## Reference

The ptrace attach and remote-call approach was compared with [AndKittyInjector](https://github.com/MJx0/AndKittyInjector). The custom ELF parser and linker path in this project are independent implementations intended for shared objects that cannot be loaded through the target's normal `dlopen` path.

## License

MIT. See [LICENSE](LICENSE).
