#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace injector {

struct ProcessIdentity {
    int pid{};
    std::uint64_t startTime{};
    std::uint32_t uid{};
    std::string executable;
};

struct MemoryMap {
    std::uint64_t start{};
    std::uint64_t end{};
    bool readable{};
    bool writable{};
    bool executable{};
    std::uint64_t fileOffset{};
    std::string path;
};

bool findProcessByPid(int pid, ProcessIdentity& process, std::string& error);
bool readProcessMaps(int pid, std::vector<MemoryMap>& maps, std::string& error);

class TargetProcess {
public:
    explicit TargetProcess(ProcessIdentity identity);
    ~TargetProcess();
    TargetProcess(const TargetProcess&) = delete;
    TargetProcess& operator=(const TargetProcess&) = delete;

    bool attachAll(std::string& error);
    bool detachAll(std::string& error);
    bool stillSameProcess() const;
    bool readMemory(std::uint64_t address, void* output, std::size_t size) const;
    bool writeMemory(std::uint64_t address, const void* input, std::size_t size) const;
    bool remoteSyscall(int tid, std::uint64_t number,
                       const std::array<std::uint64_t, 6>& args,
                       std::int64_t& result, std::string& error);
    bool remoteMmap(int tid, std::uint64_t size, std::uint64_t& address, std::string& error,
                    std::uint64_t protection = 3);
    bool remoteMprotect(int tid, std::uint64_t address, std::uint64_t size,
                        std::uint64_t protection, std::string& error);
    bool remoteMunmap(int tid, std::uint64_t address, std::uint64_t size, std::string& error);
    bool remoteCall(int tid, std::uint64_t function,
                    const std::array<std::uint64_t, 8>& args,
                    std::int64_t& result, std::string& error);

    const ProcessIdentity& identity() const { return identity_; }
    const std::vector<int>& stoppedThreads() const { return stoppedThreads_; }

private:
    bool waitForStop(int tid, int timeoutMs, int& status) const;
    bool getRegisters(int tid, void* registers, std::size_t size) const;
    bool setRegisters(int tid, const void* registers, std::size_t size) const;
    bool findSyscallInstruction(std::uint64_t& address, std::string& error) const;
    bool findBreakInstruction(std::uint64_t& address, std::string& error) const;

    ProcessIdentity identity_;
    std::vector<int> stoppedThreads_;
    std::map<int, int> pendingSignals_;
    int memoryFd_{-1};
};

} // namespace injector
