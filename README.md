# PtraceInjectLoader

**Ptrace Inject Remote ELF Loader**，面向 Android AArch64。

PtraceInjectLoader 是一个原生命令行工具，用于在已经运行的目标进程中加载 ELF64 AArch64 共享对象（DSO）。目标进程通过 PID 指定。工具使用 Linux `ptrace` 和 AArch64 远程系统调用，在目标地址空间中自行完成 ELF 映像布局、内容写入、依赖解析、重定位和入口调用。

输入文件的准确格式是 ELF64 AArch64 `ET_DYN` 共享对象，通常使用 `.so` 后缀。它不是通过 `main` 作为独立进程启动，而是在加载和重定位完成后，由 injector 调用指定的导出函数符号。该 DSO 本身不会交给目标进程的 `dlopen` 加载；对于 `DT_NEEDED` 中已经存在于目标 linker namespace 的标准系统库，loader 可以通过目标 linker 获取依赖句柄并解析符号。

## 构建

项目只支持 Android `arm64-v8a`。使用 Android NDK、CMake 和 Ninja 构建：

```powershell
cmake -S . -B cmake-build-debug -G Ninja `
  -DCMAKE_MAKE_PROGRAM="<path-to-ninja>/ninja.exe" `
  -DCMAKE_TOOLCHAIN_FILE="<path-to-android-ndk>/build/cmake/android.toolchain.cmake" `
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26
cmake --build cmake-build-debug --parallel
```

输出文件：

```text
cmake-build-debug/PtraceInjectLoader
```

在 CLion 中，将 CMake Profile 的构建目录设置为 `cmake-build-debug`，并在 Toolchain File 中选择 Android NDK 的 `build/cmake/android.toolchain.cmake`。

## 使用

查看 ELF 共享对象的信息，不接触目标进程：

```sh
/data/local/tmp/PtraceInjectLoader --inspect /data/local/tmp/libexample.so
```

以 root 身份向指定 PID 注入：

```sh
/data/local/tmp/PtraceInjectLoader \
  --inject --pid 1234 /data/local/tmp/libexample.so \
  --entry surface_tools_start
```

指定的导出函数符号可以接收最多 8 个 AArch64 整数或指针参数：

```sh
--arg0 0x1234 --arg1 7
```

Injector 要求以 root 运行。注入前会读取当前 SELinux 状态。如果当前是 `Enforcing`，工具会在注入窗口临时执行 `setenforce 0`，完成或失败清理后恢复原状态。如果原本已经是 `Permissive`，工具不会修改状态。

## 加载流程

1. 校验目标 PID，并确认目标可执行文件是 ELF64 AArch64。
2. 使用 `ptrace` 附加并暂停目标进程的全部线程。
3. 远程调用 `mmap`，申请一整块匿名 `RWX` 内存。
4. 写入 ELF 文件内容，并将 BSS 和段间空洞保持为零。
5. 解析目标进程已映射的 ELF，解析标准依赖库和 linker 符号。
6. 处理 RELA、RELR、绝对地址、PC-relative、PLT、GLOB_DAT、RELATIVE、IRELATIVE 和 GNU IFUNC。
7. 执行 `DT_INIT`、`DT_INIT_ARRAY`，再调用指定入口。
8. 恢复寄存器，解除所有线程的 ptrace 附加，验证目标进程代际，并恢复 SELinux 状态。

带有 ELF TLS 的 SO 文件当前会被明确拒绝。为每个目标线程注册新的 TLS 模块需要 Android linker/runtime 的额外集成，不属于当前 loader 的支持范围。

## 共享对象支持范围和限制

- 仅支持 Android AArch64。
- 支持 ELF64 AArch64 `ET_DYN` 共享对象（DSO），通常使用 `.so` 后缀。
- 使用一整块连续的零填充映像覆盖所有 `PT_LOAD` 段，包括 BSS 和段间空洞。
- `DT_NEEDED` 依赖必须已经存在于目标 Android linker namespace 中。
- 支持 RELA、压缩 RELR、AArch64 绝对地址和 PC-relative 重定位、PLT、GLOB_DAT、RELATIVE、IRELATIVE 以及 GNU IFUNC。
- 支持执行 `DT_INIT` 和 `DT_INIT_ARRAY`。
- 支持指定 `STT_FUNC` 或 `STT_GNU_IFUNC` 入口。

当前不注册 ELF TLS 模块，不支持卸载映像或在成功调用入口后执行 finalizer，也不提供 C++ 异常域集成、linker namespace 创建或 Android linker 替代实现。RWX 分配是设计的一部分。注入前会保存当前 SELinux 状态，并在正常完成或失败清理后恢复。

Injector 必须以 root 运行。调用者需要自行选择有效的目标 PID，并确认共享对象适用于该目标进程。指定的入口必须是共享对象中的导出函数符号，不是进程的 `main` 入口。

## 参考项目

ptrace 附加和远程调用方式参考了 [AndKittyInjector](https://github.com/MJx0/AndKittyInjector)。本项目的 ELF 解析和自定义加载流程是独立实现，目标是处理不能直接通过目标进程正常 `dlopen` 路径加载的 SO 文件。

## 许可证

MIT，详见 [LICENSE](LICENSE)。
