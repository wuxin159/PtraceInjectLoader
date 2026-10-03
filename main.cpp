#include "elf_image.hpp"
#include "linker_loader.hpp"
#include "target_process.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>

namespace {

constexpr std::uint64_t kMaxPayloadBytes = 128ull * 1024 * 1024;
constexpr std::uint64_t kMaxImageBytes = 256ull * 1024 * 1024;

bool parseNumber(const std::string& text, std::uint64_t& value) {
    errno = 0;
    char* end = nullptr;
    const auto parsed = std::strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str() || *end != '\0')
        return false;
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool parsePid(const std::string& text, int& pid) {
    std::uint64_t value = 0;
    if (!parseNumber(text, value) || value == 0 || value > std::numeric_limits<int>::max())
        return false;
    pid = static_cast<int>(value);
    return true;
}

bool readPayload(const std::string& path, std::vector<std::uint8_t>& bytes, std::string& error) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "cannot open payload: " + path;
        return false;
    }
    const auto end = input.tellg();
    if (end <= 0 || static_cast<std::uint64_t>(end) > kMaxPayloadBytes ||
        static_cast<std::uint64_t>(end) > std::numeric_limits<std::size_t>::max()) {
        error = "payload is empty or exceeds 128 MiB";
        return false;
    }
    bytes.resize(static_cast<std::size_t>(end));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        error = "short read from payload";
        return false;
    }
    return true;
}

bool runSetenforce(int value, std::string& error) {
    const pid_t child = fork();
    if (child < 0) {
        error = "fork for setenforce failed: " + std::string(std::strerror(errno));
        return false;
    }
    if (child == 0) {
        const std::string text = std::to_string(value);
        execl("/system/bin/setenforce", "setenforce", text.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        error = "setenforce " + std::to_string(value) + " failed";
        return false;
    }
    return true;
}

class ScopedPermissive {
public:
    bool enter(std::string& error) {
        std::ifstream enforce("/sys/fs/selinux/enforce");
        int state = -1;
        if (!(enforce >> state) || (state != 0 && state != 1)) {
            error = "cannot read /sys/fs/selinux/enforce";
            return false;
        }
        original_ = state;
        if (state == 1) {
            if (!runSetenforce(0, error))
                return false;
            changed_ = true;
        }
        return true;
    }

    bool restore(std::string& error) {
        if (!changed_)
            return true;
        const bool ok = runSetenforce(original_, error);
        if (ok)
            changed_ = false;
        return ok;
    }

    ~ScopedPermissive() {
        if (changed_) {
            std::string ignored;
            runSetenforce(original_, ignored);
        }
    }

private:
    int original_{-1};
    bool changed_{false};
};

bool inspectPayload(const std::string& path) {
    std::vector<std::uint8_t> bytes;
    std::string error;
    injector::ElfImage image;
    if (!readPayload(path, bytes, error) || !injector::parseElfImage(bytes, kMaxImageBytes, image, error)) {
        std::cerr << "failed: ELF validation: " << error << '\n';
        return false;
    }
    std::cout << "ELF: AArch64 ET_DYN, little-endian ELF64\n"
              << "file_bytes: " << bytes.size() << '\n'
              << "image_virtual_base: 0x" << std::hex << image.lowestPage << std::dec << '\n'
              << "single_mapping_bytes: " << image.imageSize << '\n'
              << "load_segments: " << image.segments.size() << '\n'
              << "relocations: " << image.relocationCount << '\n'
              << "relative_relocations: " << image.relativeRelocationCount << '\n'
              << "dynamic_symbols: " << image.symbols.size() << '\n'
              << "init_array_entries: " << image.initArrayCount << '\n'
              << "PT_TLS: " << (image.hasTls ? "present (unsupported)" : "absent") << '\n'
              << "dependencies:" << '\n';
    for (const auto& library : image.neededLibraries)
        std::cout << "  " << library << '\n';
    std::map<std::uint32_t, std::size_t> relocationsByType;
    for (const auto& relocation : image.relocations)
        ++relocationsByType[relocation.type];
    std::cout << "relocation_types:" << '\n';
    for (const auto& [type, count] : relocationsByType)
        std::cout << "  type=" << type << " parsed=" << count << '\n';
    if (image.relativeRelocationCount != 0)
        std::cout << "  type=RELR parsed=" << image.relativeRelocationCount << '\n';
    return true;
}

bool isEntryFunction(const injector::DynamicSymbol& symbol, const std::string& name) {
    const auto type = symbol.info & 0x0f;
    const auto binding = symbol.info >> 4;
    return symbol.name == name && symbol.sectionIndex != 0 &&
           (binding == 1 || binding == 2) && (type == 2 || type == 10);
}

bool injectPayload(int pid, const std::string& path, const std::string& entryName,
                   const std::array<std::uint64_t, 8>& entryArgs) {
    if (geteuid() != 0) {
        std::cerr << "failed: PtraceInjectLoader must run as root\n";
        return false;
    }

    ScopedPermissive selinux;
    std::string error;
    if (!selinux.enter(error)) {
        std::cerr << "state=failed stage=selinux-enter error=" << error << '\n';
        return false;
    }
    injector::ProcessIdentity identity;
    if (!injector::findProcessByPid(pid, identity, error)) {
        std::cerr << "state=failed stage=discover error=" << error << '\n';
        return false;
    }
    std::vector<std::uint8_t> payloadBytes;
    if (!readPayload(path, payloadBytes, error)) {
        std::cerr << "state=failed stage=validating error=" << error << '\n';
        return false;
    }
    injector::ElfImage payloadElf;
    if (!injector::parseElfImage(payloadBytes, kMaxImageBytes, payloadElf, error)) {
        std::cerr << "state=failed stage=validating error=" << error << '\n';
        return false;
    }
    if (!std::any_of(payloadElf.symbols.begin(), payloadElf.symbols.end(),
                     [&](const auto& symbol) { return isEntryFunction(symbol, entryName); })) {
        std::cerr << "state=failed stage=validating error=entry symbol not found: " << entryName << '\n';
        return false;
    }

    injector::TargetProcess target(identity);
    std::cerr << "state=attaching pid=" << identity.pid << " executable=" << identity.executable
              << " start_time=" << identity.startTime << '\n';
    if (!target.attachAll(error)) {
        std::cerr << "state=failed stage=attaching error=" << error << '\n';
        return false;
    }
    const int tid = target.stoppedThreads().front();
    std::uint64_t imageBase = 0;
    if (!target.remoteMmap(tid, payloadElf.imageSize, imageBase, error, 7)) {
        std::cerr << "state=failed stage=target-rwx-alloc error=" << error << '\n';
        std::string ignored;
        target.detachAll(ignored);
        return false;
    }
    std::cerr << "state=loading-with-custom-linker path=" << path
              << " file_bytes=" << payloadBytes.size()
              << " image_bytes=" << payloadElf.imageSize
              << " target_base=0x" << std::hex << imageBase << std::dec
              << " entry=" << entryName << '\n';
    std::int64_t entryResult = 0;
    if (!injector::loadWithTargetMemory(target, tid, payloadElf, entryName,
                                        entryArgs, imageBase, entryResult, error)) {
        std::cerr << "state=failed stage=custom-linker error=" << error << '\n';
        std::string ignored;
        target.detachAll(ignored);
        return false;
    }
    std::string detachError;
    if (!target.detachAll(detachError)) {
        std::cerr << "state=rollback-incomplete stage=detach error=" << detachError << '\n';
        return false;
    }
    if (!target.stillSameProcess()) {
        std::cerr << "state=failed stage=verify error=target exited or restarted\n";
        return false;
    }
    std::cout << "state=active pid=" << identity.pid << " executable=" << identity.executable
              << " start_time=" << identity.startTime << " path=" << path
              << " entry_result=" << entryResult << '\n';
    if (!selinux.restore(error)) {
        std::cerr << "state=rollback-incomplete stage=selinux-restore error=" << error << '\n';
        return false;
    }
    return true;
}

bool parseInjectArgs(int argc, char** argv, int& pid, std::string& payload,
                     std::string& entry, std::array<std::uint64_t, 8>& args) {
    bool havePid = false;
    bool haveEntry = false;
    for (int i = 2; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "--pid" && i + 1 < argc) {
            havePid = parsePid(argv[++i], pid);
        } else if (option == "--entry" && i + 1 < argc) {
            entry = argv[++i];
            haveEntry = !entry.empty();
        } else if (option.rfind("--arg", 0) == 0 && option.size() == 6 &&
                   option[5] >= '0' && option[5] <= '7' && i + 1 < argc) {
            if (!parseNumber(argv[++i], args[static_cast<std::size_t>(option[5] - '0')]))
                return false;
        } else if (option.rfind("--", 0) != 0 && payload.empty()) {
            payload = option;
        } else {
            return false;
        }
    }
    return havePid && haveEntry && !payload.empty();
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--inspect")
        return inspectPayload(argv[2]) ? 0 : 1;
    if (argc >= 6 && std::string(argv[1]) == "--inject") {
        int pid = 0;
        std::string payload;
        std::string entry;
        std::array<std::uint64_t, 8> args{};
        if (!parseInjectArgs(argc, argv, pid, payload, entry, args)) {
            std::cerr << "Usage: PtraceInjectLoader --inject --pid <pid> <payload.so>"
                         " --entry <symbol> [--arg0 value ... --arg7 value]\n";
            return 2;
        }
        return injectPayload(pid, payload, entry, args) ? 0 : 1;
    }
    std::cerr << "Usage: PtraceInjectLoader --inspect <payload.so>\n"
                 "       PtraceInjectLoader --inject --pid <pid> <payload.so>"
                 " --entry <symbol> [--arg0 value ... --arg7 value]\n";
    return 2;
}
