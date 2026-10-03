#include "target_process.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <linux/elf.h>
#include <linux/ptrace.h>
#include <sstream>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <asm/ptrace.h>

namespace injector {
namespace {

constexpr std::uint32_t kSvc0Instruction = 0xd4000001;
constexpr std::uint32_t kBrk0Instruction = 0xd4200000;
constexpr std::uint64_t kMapPrivateAnonymous = 0x22;
constexpr std::uint64_t kProtReadWrite = 3;
constexpr std::uint64_t kRemoteCallStackSize = 1024 * 1024;

bool parsePositiveInt(const char* text, int& value) {
    if (!text || !*text)
        return false;
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed <= 0 || parsed > INT_MAX)
        return false;
    value = static_cast<int>(parsed);
    return true;
}

bool readStartTime(int pid, std::uint64_t& startTime) {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!std::getline(stat, line))
        return false;
    const auto close = line.rfind(')');
    if (close == std::string::npos || close + 2 >= line.size())
        return false;
    std::istringstream fields(line.substr(close + 2));
    std::string field;
    for (int index = 0; index <= 19; ++index) {
        if (!(fields >> field))
            return false;
        if (index == 19) {
            try {
                startTime = std::stoull(field);
            } catch (...) {
                return false;
            }
        }
    }
    return true;
}

bool readUid(int pid, std::uint32_t& uid) {
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    std::string key;
    while (status >> key) {
        if (key == "Uid:") {
            std::uint64_t parsed = 0;
            if (!(status >> parsed) || parsed > std::numeric_limits<std::uint32_t>::max())
                return false;
            uid = static_cast<std::uint32_t>(parsed);
            return true;
        }
        std::string rest;
        std::getline(status, rest);
    }
    return false;
}

bool isAArch64ElfExecutable(int pid) {
    const std::string path = "/proc/" + std::to_string(pid) + "/exe";
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    std::uint8_t header[20]{};
    const auto count = pread(fd, header, sizeof(header), 0);
    close(fd);
    if (count != static_cast<ssize_t>(sizeof(header)))
        return false;
    return header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' &&
           header[4] == 2 && header[5] == 1 && header[6] == 1 &&
           header[18] == 183 && header[19] == 0;
}

bool listThreadIds(int pid, std::vector<int>& tids) {
    tids.clear();
    const std::string path = "/proc/" + std::to_string(pid) + "/task";
    DIR* dir = opendir(path.c_str());
    if (!dir)
        return false;
    while (dirent* entry = readdir(dir)) {
        int tid = 0;
        if (parsePositiveInt(entry->d_name, tid))
            tids.push_back(tid);
    }
    closedir(dir);
    std::sort(tids.begin(), tids.end());
    return true;
}

} // namespace

bool findProcessByPid(int pid, ProcessIdentity& process, std::string& error) {
    error.clear();
    if (pid <= 0) {
        error = "invalid target PID";
        return false;
    }
    char exeLink[PATH_MAX]{};
    const std::string linkPath = "/proc/" + std::to_string(pid) + "/exe";
    const auto length = readlink(linkPath.c_str(), exeLink, sizeof(exeLink) - 1);
    if (length <= 0) {
        error = "cannot resolve target executable: " + std::string(std::strerror(errno));
        return false;
    }
    exeLink[length] = '\0';
    if (!isAArch64ElfExecutable(pid)) {
        error = "target executable is not little-endian ELF64 AArch64";
        return false;
    }
    ProcessIdentity candidate;
    candidate.pid = pid;
    candidate.executable = exeLink;
    if (!readStartTime(pid, candidate.startTime) || !readUid(pid, candidate.uid)) {
        error = "cannot read target process identity";
        return false;
    }
    process = std::move(candidate);
    return true;
}

bool readProcessMaps(int pid, std::vector<MemoryMap>& maps, std::string& error) {
    maps.clear();
    error.clear();
    std::ifstream input("/proc/" + std::to_string(pid) + "/maps");
    if (!input) {
        error = "cannot read target maps: " + std::string(std::strerror(errno));
        return false;
    }
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream row(line);
        std::string range, permissions, offset, device;
        unsigned long inode = 0;
        if (!(row >> range >> permissions >> offset >> device >> inode))
            continue;
        const auto dash = range.find('-');
        if (dash == std::string::npos)
            continue;
        MemoryMap map;
        try {
            map.start = std::stoull(range.substr(0, dash), nullptr, 16);
            map.end = std::stoull(range.substr(dash + 1), nullptr, 16);
            map.fileOffset = std::stoull(offset, nullptr, 16);
        } catch (...) {
            continue;
        }
        if (map.end <= map.start)
            continue;
        map.readable = permissions.size() > 0 && permissions[0] == 'r';
        map.writable = permissions.size() > 1 && permissions[1] == 'w';
        map.executable = permissions.size() > 2 && permissions[2] == 'x';
        std::getline(row, map.path);
        const auto first = map.path.find_first_not_of(' ');
        if (first != std::string::npos)
            map.path.erase(0, first);
        maps.push_back(std::move(map));
    }
    return true;
}

TargetProcess::TargetProcess(ProcessIdentity identity) : identity_(std::move(identity)) {}

TargetProcess::~TargetProcess() {
    std::string ignored;
    detachAll(ignored);
    if (memoryFd_ >= 0)
        close(memoryFd_);
}

bool TargetProcess::waitForStop(int tid, int timeoutMs, int& status) const {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        const auto result = waitpid(tid, &status, __WALL | WNOHANG);
        if (result == tid)
            return WIFSTOPPED(status);
        if (result < 0 && errno != EINTR)
            return false;
        if (std::chrono::steady_clock::now() >= deadline) {
            errno = ETIMEDOUT;
            return false;
        }
        usleep(1000);
    }
}

bool TargetProcess::attachAll(std::string& error) {
    error.clear();
    if (!stillSameProcess()) {
        error = "target process generation changed before attach";
        return false;
    }
    for (unsigned pass = 0; pass < 16; ++pass) {
        std::vector<int> tids;
        if (!listThreadIds(identity_.pid, tids)) {
            error = "cannot enumerate target threads: " + std::string(std::strerror(errno));
            detachAll(error);
            return false;
        }
        bool attachedNew = false;
        for (const int tid : tids) {
            if (std::find(stoppedThreads_.begin(), stoppedThreads_.end(), tid) != stoppedThreads_.end())
                continue;
            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != 0) {
                if (errno == ESRCH)
                    continue;
                error = "ptrace attach failed for tid " + std::to_string(tid) + ": " + std::strerror(errno);
                std::string detachError;
                detachAll(detachError);
                if (!detachError.empty())
                    error += "; " + detachError;
                return false;
            }
            int status = 0;
            if (!waitForStop(tid, 3000, status)) {
                error = "timed out waiting for ptrace stop on tid " + std::to_string(tid);
                stoppedThreads_.push_back(tid);
                std::string detachError;
                detachAll(detachError);
                if (!detachError.empty())
                    error += "; " + detachError;
                return false;
            }
            stoppedThreads_.push_back(tid);
            attachedNew = true;
        }
        if (!attachedNew)
            break;
    }
    std::vector<int> finalTids;
    if (!listThreadIds(identity_.pid, finalTids)) {
        error = "cannot verify final target thread inventory: " + std::string(std::strerror(errno));
        std::string detachError;
        detachAll(detachError);
        if (!detachError.empty())
            error += "; " + detachError;
        return false;
    }
    for (const int tid : finalTids) {
        if (std::find(stoppedThreads_.begin(), stoppedThreads_.end(), tid) == stoppedThreads_.end()) {
            error = "target thread inventory did not stabilize; untracked tid " + std::to_string(tid);
            std::string detachError;
            detachAll(detachError);
            if (!detachError.empty())
                error += "; " + detachError;
            return false;
        }
    }
    if (!stillSameProcess()) {
        error = "target process exited or restarted during attach";
        std::string detachError;
        detachAll(detachError);
        if (!detachError.empty())
            error += "; " + detachError;
        return false;
    }
    if (stoppedThreads_.empty()) {
        error = "no target threads were attached";
        return false;
    }
    memoryFd_ = open(("/proc/" + std::to_string(identity_.pid) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
    if (memoryFd_ < 0) {
        error = "cannot open target memory: " + std::string(std::strerror(errno));
        std::string detachError;
        detachAll(detachError);
        if (!detachError.empty())
            error += "; " + detachError;
        return false;
    }
    return true;
}

bool TargetProcess::detachAll(std::string& error) {
    error.clear();
    bool success = true;
    for (auto it = stoppedThreads_.rbegin(); it != stoppedThreads_.rend(); ++it) {
        const auto signal = pendingSignals_.find(*it);
        const int deliverSignal = signal == pendingSignals_.end() ? 0 : signal->second;
        if (ptrace(PTRACE_DETACH, *it, nullptr,
                   reinterpret_cast<void*>(static_cast<std::intptr_t>(deliverSignal))) != 0 && errno != ESRCH) {
            if (success)
                error = "ptrace detach failed for tid " + std::to_string(*it) + ": " + std::strerror(errno);
            success = false;
        }
    }
    stoppedThreads_.clear();
    pendingSignals_.clear();
    if (memoryFd_ >= 0) {
        close(memoryFd_);
        memoryFd_ = -1;
    }
    return success;
}

bool TargetProcess::stillSameProcess() const {
    ProcessIdentity current;
    std::string error;
    return findProcessByPid(identity_.pid, current, error) && current.pid == identity_.pid &&
           current.startTime == identity_.startTime && current.executable == identity_.executable;
}

bool TargetProcess::readMemory(std::uint64_t address, void* output, std::size_t size) const {
    if (memoryFd_ < 0 || address > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()))
        return false;
    auto* bytes = static_cast<std::uint8_t*>(output);
    std::size_t done = 0;
    while (done < size) {
        const auto count = pread(memoryFd_, bytes + done, size - done, static_cast<off_t>(address + done));
        if (count <= 0)
            return false;
        done += static_cast<std::size_t>(count);
    }
    return true;
}

bool TargetProcess::writeMemory(std::uint64_t address, const void* input, std::size_t size) const {
    const auto* bytes = static_cast<const std::uint8_t*>(input);
    std::size_t done = 0;
#ifdef SYS_process_vm_writev
    while (done < size) {
        iovec local{const_cast<std::uint8_t*>(bytes + done), size - done};
        iovec remote{reinterpret_cast<void*>(static_cast<std::uintptr_t>(address + done)), size - done};
        const auto count = syscall(SYS_process_vm_writev, identity_.pid, &local, 1, &remote, 1, 0);
        if (count <= 0)
            break;
        done += static_cast<std::size_t>(count);
    }
    if (done == size)
        return true;
#endif
    if (stoppedThreads_.empty())
        return false;
    const int tid = stoppedThreads_.front();
    constexpr std::size_t wordSize = sizeof(long);
    while (done < size) {
        long word = 0;
        const std::size_t remaining = std::min(wordSize, size - done);
        if (remaining != wordSize && !readMemory(address + done, &word, wordSize))
            return false;
        std::memcpy(&word, bytes + done, remaining);
        errno = 0;
        if (ptrace(PTRACE_POKEDATA, tid,
                   reinterpret_cast<void*>(static_cast<std::uintptr_t>(address + done)),
                   reinterpret_cast<void*>(word)) != 0 && errno != 0)
            return false;
        done += remaining;
    }
    return true;
}

bool TargetProcess::getRegisters(int tid, void* registers, std::size_t size) const {
    iovec io{registers, size};
    return ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0 && io.iov_len == size;
}

bool TargetProcess::setRegisters(int tid, const void* registers, std::size_t size) const {
    iovec io{const_cast<void*>(registers), size};
    return ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
}

bool TargetProcess::findSyscallInstruction(std::uint64_t& address, std::string& error) const {
    std::vector<MemoryMap> maps;
    if (!readProcessMaps(identity_.pid, maps, error))
        return false;
    std::uint32_t instruction = 0;
    for (const auto& map : maps) {
        if (!map.executable || map.end - map.start < sizeof(instruction))
            continue;
        constexpr std::size_t chunkSize = 64 * 1024;
        std::vector<std::uint8_t> chunk(chunkSize + 3);
        for (std::uint64_t cursor = map.start; cursor + sizeof(instruction) <= map.end;) {
            const auto bytesToRead = static_cast<std::size_t>(std::min<std::uint64_t>(chunkSize, map.end - cursor));
            if (!readMemory(cursor, chunk.data(), bytesToRead))
                break;
            for (std::size_t offset = 0; offset + sizeof(instruction) <= bytesToRead; offset += 4) {
                std::memcpy(&instruction, chunk.data() + offset, sizeof(instruction));
                if (instruction == kSvc0Instruction) {
                    address = cursor + offset;
                    return true;
                }
            }
            if (bytesToRead <= 3)
                break;
            cursor += bytesToRead - 3;
            cursor = (cursor + 3) & ~std::uint64_t(3);
        }
    }
    error = "no aligned svc #0 instruction found in executable target mappings";
    return false;
}

bool TargetProcess::findBreakInstruction(std::uint64_t& address, std::string& error) const {
    std::vector<MemoryMap> maps;
    if (!readProcessMaps(identity_.pid, maps, error))
        return false;
    std::uint32_t instruction = 0;
    constexpr std::size_t chunkSize = 64 * 1024;
    std::vector<std::uint8_t> chunk(chunkSize + 3);
    for (const auto& map : maps) {
        if (!map.executable || map.end - map.start < sizeof(instruction))
            continue;
        for (std::uint64_t cursor = map.start; cursor + sizeof(instruction) <= map.end;) {
            const auto bytesToRead = static_cast<std::size_t>(std::min<std::uint64_t>(chunkSize, map.end - cursor));
            if (!readMemory(cursor, chunk.data(), bytesToRead))
                break;
            for (std::size_t offset = 0; offset + sizeof(instruction) <= bytesToRead; offset += 4) {
                std::memcpy(&instruction, chunk.data() + offset, sizeof(instruction));
                if ((instruction & 0xffe0001f) == kBrk0Instruction) {
                    address = cursor + offset;
                    return true;
                }
            }
            if (bytesToRead <= 3)
                break;
            cursor += bytesToRead - 3;
            cursor = (cursor + 3) & ~std::uint64_t(3);
        }
    }
    error = "no aligned brk instruction found in executable target mappings";
    return false;
}

bool TargetProcess::remoteSyscall(int tid, std::uint64_t number,
                                  const std::array<std::uint64_t, 6>& args,
                                  std::int64_t& result, std::string& error) {
    error.clear();
    if (std::find(stoppedThreads_.begin(), stoppedThreads_.end(), tid) == stoppedThreads_.end()) {
        error = "remote syscall tid is not attached and stopped";
        return false;
    }
    user_pt_regs original{};
    if (!getRegisters(tid, &original, sizeof(original))) {
        error = "PTRACE_GETREGSET failed: " + std::string(std::strerror(errno));
        return false;
    }
    std::uint64_t syscallPc = 0;
    if (!findSyscallInstruction(syscallPc, error))
        return false;
    user_pt_regs call = original;
    call.pc = syscallPc;
    call.regs[8] = number;
    for (std::size_t i = 0; i < args.size(); ++i)
        call.regs[i] = args[i];
    if (!setRegisters(tid, &call, sizeof(call))) {
        error = "PTRACE_SETREGSET failed before remote syscall: " + std::string(std::strerror(errno));
        return false;
    }
    if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) != 0) {
        error = "PTRACE_SINGLESTEP failed: " + std::string(std::strerror(errno));
        setRegisters(tid, &original, sizeof(original));
        return false;
    }
    int status = 0;
    if (!waitForStop(tid, 3000, status) || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        error = "remote syscall did not stop cleanly after svc #0";
        if (!WIFSTOPPED(status)) {
            syscall(SYS_tgkill, identity_.pid, tid, SIGSTOP);
            if (!waitForStop(tid, 3000, status)) {
                error += "; thread state could not be recovered";
                return false;
            }
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGSTOP)
            pendingSignals_[tid] = WSTOPSIG(status);
        if (!setRegisters(tid, &original, sizeof(original)))
            error += "; original registers could not be restored";
        return false;
    }
    user_pt_regs returned{};
    if (!getRegisters(tid, &returned, sizeof(returned))) {
        error = "failed to read registers after remote syscall";
        if (!setRegisters(tid, &original, sizeof(original)))
            error += "; original registers could not be restored";
        return false;
    }
    const auto raw = static_cast<std::int64_t>(returned.regs[0]);
    if (raw < 0 && raw >= -4095) {
        error = "remote syscall returned errno " + std::to_string(-raw);
        result = raw;
    } else {
        result = raw;
    }
    if (!setRegisters(tid, &original, sizeof(original))) {
        error += "; failed to restore original registers";
        return false;
    }
    return raw >= 0;
}

bool TargetProcess::remoteMmap(int tid, std::uint64_t size,
                               std::uint64_t& address, std::string& error,
                               std::uint64_t protection) {
    std::int64_t result = -1;
    const std::array<std::uint64_t, 6> args{
        0, size, protection, kMapPrivateAnonymous, static_cast<std::uint64_t>(-1), 0};
    if (!remoteSyscall(tid, __NR_mmap, args, result, error))
        return false;
    address = static_cast<std::uint64_t>(result);
    return address != 0 && address != std::numeric_limits<std::uint64_t>::max();
}

bool TargetProcess::remoteMprotect(int tid, std::uint64_t address, std::uint64_t size,
                                   std::uint64_t protection, std::string& error) {
    std::int64_t result = -1;
    const std::array<std::uint64_t, 6> args{address, size, protection, 0, 0, 0};
    return remoteSyscall(tid, __NR_mprotect, args, result, error) && result == 0;
}

bool TargetProcess::remoteMunmap(int tid, std::uint64_t address, std::uint64_t size,
                                 std::string& error) {
    std::int64_t result = -1;
    const std::array<std::uint64_t, 6> args{address, size, 0, 0, 0, 0};
    return remoteSyscall(tid, __NR_munmap, args, result, error) && result == 0;
}

bool TargetProcess::remoteCall(int tid, std::uint64_t function,
                               const std::array<std::uint64_t, 8>& args,
                               std::int64_t& result, std::string& error) {
    error.clear();
    std::uint64_t returnTrap = 0;
    if (!findBreakInstruction(returnTrap, error))
        return false;

    user_pt_regs original{};
    if (!getRegisters(tid, &original, sizeof(original))) {
        error = "PTRACE_GETREGSET failed before remote function call";
        return false;
    }
    std::array<std::uint8_t, 4096> fpState{};
    iovec fpIo{fpState.data(), fpState.size()};
    const bool hasFpState = ptrace(PTRACE_GETREGSET, tid,
        reinterpret_cast<void*>(NT_PRFPREG), &fpIo) == 0;
    if (!hasFpState || fpIo.iov_len > fpState.size()) {
        error = "PTRACE_GETREGSET(NT_PRFPREG) failed before remote function call";
        return false;
    }
    const std::size_t fpStateSize = hasFpState ? fpIo.iov_len : 0;
    auto restoreContext = [&]() {
        bool restored = setRegisters(tid, &original, sizeof(original));
        if (hasFpState) {
            iovec restoreFp{fpState.data(), fpStateSize};
            restored = ptrace(PTRACE_SETREGSET, tid,
                reinterpret_cast<void*>(NT_PRFPREG), &restoreFp) == 0 && restored;
        }
        return restored;
    };
    std::uint64_t remoteStack = 0;
    if (!remoteMmap(tid, kRemoteCallStackSize, remoteStack, error, kProtReadWrite))
        return false;

    user_pt_regs call = original;
    for (std::size_t i = 0; i < args.size(); ++i)
        call.regs[i] = args[i];
    call.regs[30] = returnTrap;
    call.sp = (remoteStack + kRemoteCallStackSize - 16) & ~std::uint64_t(15);
    call.pc = function;
    if (!setRegisters(tid, &call, sizeof(call))) {
        error = "PTRACE_SETREGSET failed before remote function call";
        std::string ignored;
        remoteMunmap(tid, remoteStack, kRemoteCallStackSize, ignored);
        return false;
    }
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) != 0) {
        error = "PTRACE_CONT failed for remote function call: " + std::string(std::strerror(errno));
        if (restoreContext()) {
            std::string ignored;
            remoteMunmap(tid, remoteStack, kRemoteCallStackSize, ignored);
        } else {
            error += "; original context could not be restored, scratch stack retained";
        }
        return false;
    }
    int status = 0;
    if (!waitForStop(tid, 10000, status)) {
        error = "timed out waiting for remote function return";
        syscall(SYS_tgkill, identity_.pid, tid, SIGSTOP);
        if (waitForStop(tid, 3000, status)) {
            if (!restoreContext()) {
                error += "; original register state could not be restored";
            } else {
                std::string ignored;
                remoteMunmap(tid, remoteStack, kRemoteCallStackSize, ignored);
            }
        } else {
            error += "; thread state could not be recovered";
        }
        return false;
    }
    user_pt_regs returned{};
    if (!getRegisters(tid, &returned, sizeof(returned))) {
        error = "failed to read registers after remote function call";
        if (restoreContext()) {
            std::string ignored;
            remoteMunmap(tid, remoteStack, kRemoteCallStackSize, ignored);
        } else {
            error += "; original context could not be restored, scratch stack retained";
        }
        return false;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
        (returned.pc != returnTrap && returned.pc != returnTrap + sizeof(kBrk0Instruction))) {
        error = "remote function stopped before returning through its trap";
        if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGSTOP)
            pendingSignals_[tid] = WSTOPSIG(status);
        if (restoreContext()) {
            std::string ignored;
            remoteMunmap(tid, remoteStack, kRemoteCallStackSize, ignored);
        } else {
            error += "; original context could not be restored, scratch stack retained";
        }
        return false;
    }
    result = static_cast<std::int64_t>(returned.regs[0]);
    if (!restoreContext()) {
        error = "failed to restore target registers after remote function call";
        return false;
    }
    std::string cleanupError;
    if (!remoteMunmap(tid, remoteStack, kRemoteCallStackSize, cleanupError)) {
        error = "remote call returned but scratch stack cleanup failed: " + cleanupError;
        return false;
    }
    return true;
}

} // namespace injector
