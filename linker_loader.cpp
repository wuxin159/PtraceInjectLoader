#include "linker_loader.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sys/mman.h>
#include <sys/syscall.h>

namespace injector {
namespace {

constexpr std::uint64_t kPageSize = 4096;
constexpr std::size_t kMaxPayloadSize = 128 * 1024 * 1024;
constexpr std::size_t kScratchSize = 64 * 1024;
constexpr std::uint64_t kRtldNow = 2;
constexpr std::uint64_t kRtldGlobal = 0x100;

constexpr std::uint32_t kRAbs32 = 258;
constexpr std::uint32_t kRAbs64 = 257;
constexpr std::uint32_t kRAbs16 = 259;
constexpr std::uint32_t kRPrel64 = 260;
constexpr std::uint32_t kRPrel32 = 261;
constexpr std::uint32_t kRPrel16 = 262;
constexpr std::uint32_t kRGlobDat = 1025;
constexpr std::uint32_t kRJumpSlot = 1026;
constexpr std::uint32_t kRRelative = 1027;
constexpr std::uint32_t kRIrelative = 1032;
constexpr std::uint32_t kRNone = 0;
constexpr std::uint8_t kSttGnuIfunc = 10;
constexpr std::uint16_t kShnAbs = 0xfff1;

std::string canonicalMapPath(const MemoryMap& map) {
    std::string path = map.path;
    constexpr char suffix[] = " (deleted)";
    if (path.size() >= sizeof(suffix) - 1 &&
        path.compare(path.size() - (sizeof(suffix) - 1), sizeof(suffix) - 1, suffix) == 0)
        path.resize(path.size() - (sizeof(suffix) - 1));
    return path;
}

bool readElfFile(const std::string& path, std::vector<std::uint8_t>& bytes, std::string& error) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "cannot open ELF " + path + ": " + std::strerror(errno);
        return false;
    }
    const auto end = input.tellg();
    if (end <= 0 || static_cast<std::uint64_t>(end) > kMaxPayloadSize ||
        static_cast<std::uint64_t>(end) > std::numeric_limits<std::size_t>::max()) {
        error = "ELF is empty or exceeds 128 MiB";
        return false;
    }
    bytes.resize(static_cast<std::size_t>(end));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        error = "short read from ELF " + path;
        return false;
    }
    return true;
}

bool loadBiasFor(const ElfImage& image,
                 const std::vector<MemoryMap>& maps,
                 const std::string& path,
                 std::uint64_t& loadBias) {
    for (const auto& segment : image.segments) {
        if (segment.fileSize == 0)
            continue;
        const auto alignedOffset = segment.fileOffset & ~(kPageSize - 1);
        const auto alignedAddress = segment.virtualAddress & ~(kPageSize - 1);
        for (const auto& map : maps) {
            if (canonicalMapPath(map) == path && map.fileOffset == alignedOffset && map.start >= alignedAddress) {
                loadBias = map.start - alignedAddress;
                return true;
            }
        }
    }
    return false;
}

bool readRemoteString(TargetProcess& target, std::uint64_t address,
                      std::string& value, std::string& error) {
    value.clear();
    for (std::size_t i = 0; i < 1024; ++i) {
        char byte = 0;
        if (!target.readMemory(address + i, &byte, 1)) {
            error = "failed to read target linker error string";
            return false;
        }
        if (byte == '\0')
            return true;
        value.push_back(byte);
    }
    error = "target linker error string exceeded 1024 bytes";
    return false;
}

bool linkerError(TargetProcess& target, const ResolvedTargetSymbol& dlerror,
                 std::string& error) {
    std::int64_t pointer = 0;
    std::string callError;
    if (!target.remoteCall(target.stoppedThreads().front(), dlerror.address, {}, pointer, callError) || pointer == 0)
        return false;
    return readRemoteString(target, static_cast<std::uint64_t>(pointer), error, callError);
}

bool addSignedOffset(std::uint64_t base, std::int64_t delta, std::uint64_t& result) {
    if (delta >= 0) {
        const auto amount = static_cast<std::uint64_t>(delta);
        if (base > std::numeric_limits<std::uint64_t>::max() - amount)
            return false;
        result = base + amount;
        return true;
    }
    const auto amount = static_cast<std::uint64_t>(-(delta + 1)) + 1;
    if (base < amount)
        return false;
    result = base - amount;
    return true;
}

bool calculateSignedRelative(std::uint64_t symbol,
                             std::int64_t addend,
                             std::uint64_t place,
                             unsigned bits,
                             std::uint64_t& encoded) {
    const __int128 value = static_cast<__int128>(symbol) +
                           static_cast<__int128>(addend) -
                           static_cast<__int128>(place);
    const __int128 minimum = -(__int128{1} << (bits - 1));
    const __int128 maximum = (__int128{1} << (bits - 1)) - 1;
    if (value < minimum || value > maximum)
        return false;
    const std::uint64_t mask = bits == 64 ? std::numeric_limits<std::uint64_t>::max()
                                          : (std::uint64_t{1} << bits) - 1;
    encoded = static_cast<std::uint64_t>(value) & mask;
    return true;
}

} // namespace

bool resolveTargetSymbol(const std::vector<MemoryMap>& maps,
                         const std::string& name,
                         ResolvedTargetSymbol& symbol,
                         std::string& error) {
    symbol = {};
    error.clear();
    std::set<std::string> paths;
    for (const auto& map : maps) {
        const auto path = canonicalMapPath(map);
        if (!map.executable || path.empty() || path.front() != '/' || !paths.insert(path).second)
            continue;
        std::vector<std::uint8_t> bytes;
        std::string parseError;
        if (!readElfFile(path, bytes, parseError))
            continue;
        ElfImage image;
        if (!parseElfImage(bytes, 512ull * 1024 * 1024, image, parseError))
            continue;
        std::uint64_t bias = 0;
        if (!loadBiasFor(image, maps, path, bias))
            continue;
        const DynamicSymbol* match = nullptr;
        for (const auto& candidate : image.symbols) {
            if (candidate.name != name || candidate.sectionIndex == 0 || candidate.versionHidden)
                continue;
            const auto binding = candidate.info >> 4;
            const auto visibility = candidate.other & 0x03;
            if ((binding != 1 && binding != 2) || visibility == 2 || (candidate.info & 0x0f) == 6)
                continue;
            if (match == nullptr || (candidate.info >> 4) == 1)
                match = &candidate;
            if ((candidate.info >> 4) == 1)
                break;
        }
        if (!match)
            continue;
        if (match->value > std::numeric_limits<std::uint64_t>::max() - bias) {
            error = "resolved symbol address overflow for " + name;
            return false;
        }
        symbol.address = bias + match->value;
        symbol.loadBias = bias;
        symbol.libraryPath = path;
        return true;
    }
    error = "target maps contain no readable exported symbol named " + name;
    return false;
}

#if 0 // The payload is intentionally never loaded through android_dlopen_ext.
bool loadWithTargetLinker(TargetProcess& target,
                          int tid,
                          const std::vector<std::uint8_t>& payloadBytes,
                          const ElfImage& payloadElf,
                          const std::string& entryName,
                          const std::array<std::uint64_t, 8>& entryArgs,
                          std::int64_t& entryResult,
                          std::string& error) {
    error.clear();
    if (payloadBytes.empty() || payloadBytes.size() > kMaxPayloadSize) {
        error = "payload bytes are empty or exceed 128 MiB";
        return false;
    }
    if (!payloadElf.soname.empty() && payloadElf.soname.find('/') != std::string::npos) {
        error = "payload DT_SONAME contains a path separator";
        return false;
    }
    if (payloadElf.soname.empty()) {
        error = "payload must declare DT_SONAME for fd-backed linker loading";
        return false;
    }
    bool entryExists = false;
    for (const auto& symbol : payloadElf.symbols) {
        if (symbol.name == entryName && symbol.sectionIndex != 0 &&
            (symbol.info >> 4) == 1 && (symbol.info & 0x0f) == 2) {
            entryExists = true;
            break;
        }
    }
    if (!entryExists) {
        error = "payload has no defined global function " + entryName;
        return false;
    }

    std::vector<MemoryMap> maps;
    if (!readProcessMaps(target.identity().pid, maps, error))
        return false;
    ResolvedTargetSymbol androidDlopen, dlsym, dlerror;
    if (!resolveTargetSymbol(maps, "android_dlopen_ext", androidDlopen, error) ||
        !resolveTargetSymbol(maps, "dlsym", dlsym, error) ||
        !resolveTargetSymbol(maps, "dlerror", dlerror, error))
        return false;

    const auto payloadHash = hashBytes(payloadBytes);
    char memfdName[64]{};
    std::snprintf(memfdName, sizeof(memfdName), "Injector_%016llx",
                  static_cast<unsigned long long>(payloadHash));
    for (const auto& map : maps) {
        if (map.path.find(memfdName) != std::string::npos) {
            error = "this payload is already present in the current target process generation";
            return false;
        }
    }

    std::uint64_t scratch = 0;
    if (!target.remoteMmap(tid, kScratchSize, scratch, error, PROT_READ | PROT_WRITE))
        return false;
    auto cleanup = [&](int fd) {
        std::string cleanupError;
        const bool fdClosed = closeRemoteFd(target, tid, fd, cleanupError);
        const bool unmapped = target.remoteMunmap(tid, scratch, kScratchSize, cleanupError);
        if ((!fdClosed || !unmapped) && error.empty())
            error = cleanupError.empty() ? "remote loader scratch cleanup failed" : cleanupError;
        return fdClosed && unmapped;
    };

    const std::uint64_t nameAddress = scratch;
    if (!target.writeMemory(nameAddress, memfdName, std::strlen(memfdName) + 1)) {
        error = "failed to write remote memfd name";
        cleanup(-1);
        return false;
    }
    std::int64_t fdResult = -1;
    if (!target.remoteSyscall(tid, __NR_memfd_create,
                              {nameAddress, kMemfdCloexec, 0, 0, 0, 0}, fdResult, error)) {
        cleanup(-1);
        return false;
    }
    const int remoteFd = static_cast<int>(fdResult);

    for (std::size_t offset = 0; offset < payloadBytes.size();) {
        const auto count = std::min(kWriteChunkSize, payloadBytes.size() - offset);
        const auto dataAddress = scratch + 4096;
        if (!target.writeMemory(dataAddress, payloadBytes.data() + offset, count)) {
            error = "failed to copy payload bytes into target staging buffer";
            cleanup(remoteFd);
            return false;
        }
        std::int64_t written = -1;
        if (!target.remoteSyscall(tid, __NR_write,
                                  {static_cast<std::uint64_t>(remoteFd), dataAddress, count, 0, 0, 0},
                                  written, error) || written <= 0 ||
            static_cast<std::size_t>(written) != count) {
            if (error.empty())
                error = "short write while populating target memfd";
            cleanup(remoteFd);
            return false;
        }
        offset += count;
    }

    const std::string soname = payloadElf.soname;
    const std::uint64_t sonameAddress = scratch + 56 * 1024;
    const std::uint64_t infoAddress = scratch + 57 * 1024;
    const std::uint64_t entryNameAddress = scratch + 58 * 1024;
    AndroidDlextInfo64 info{};
    info.flags = kAndroidDlextUseLibraryFd | kAndroidDlextForceLoad;
    info.relroFd = -1;
    info.libraryFd = remoteFd;
    if (!target.writeMemory(sonameAddress, soname.c_str(), soname.size() + 1) ||
        !target.writeMemory(infoAddress, &info, sizeof(info))) {
        error = "failed to write android_dlextinfo into target memory";
        cleanup(remoteFd);
        return false;
    }

    std::int64_t handle = 0;
    if (!target.remoteCall(tid, androidDlopen.address,
                           {sonameAddress, kRtldNow, infoAddress, 0, 0, 0, 0, 0}, handle, error) || handle == 0) {
        std::string callError = error;
        std::int64_t dlerrorPointer = 0;
        std::string linkerError;
        if (target.remoteCall(tid, dlerror.address, {}, dlerrorPointer, linkerError) && dlerrorPointer != 0) {
            if (readRemoteString(target, static_cast<std::uint64_t>(dlerrorPointer), linkerError, callError))
                callError = linkerError;
        } else if (!linkerError.empty()) {
            callError = linkerError;
        }
        error = "android_dlopen_ext failed" + (callError.empty() ? std::string{} : ": " + callError);
        cleanup(remoteFd);
        return false;
    }

    if (!target.writeMemory(entryNameAddress, entryName.c_str(), entryName.size() + 1)) {
        error = "failed to write entry symbol name";
        cleanup(remoteFd);
        return false;
    }
    std::int64_t entryAddress = 0;
    if (!target.remoteCall(tid, dlsym.address,
                           {static_cast<std::uint64_t>(handle), entryNameAddress}, entryAddress, error) ||
        entryAddress == 0) {
        std::string callError = error;
        std::int64_t dlerrorPointer = 0;
        std::string linkerError;
        if (target.remoteCall(tid, dlerror.address, {}, dlerrorPointer, linkerError) && dlerrorPointer != 0) {
            if (readRemoteString(target, static_cast<std::uint64_t>(dlerrorPointer), linkerError, callError))
                callError = linkerError;
        } else if (!linkerError.empty()) {
            callError = linkerError;
        }
        error = "target dlsym failed for " + entryName + (callError.empty() ? std::string{} : ": " + callError);
        cleanup(remoteFd);
        return false;
    }
    if (!target.remoteCall(tid, static_cast<std::uint64_t>(entryAddress), entryArgs,
                           entryResult, error)) {
        error = "payload entry call failed: " + error;
        cleanup(remoteFd);
        return false;
    }
    if (!cleanup(remoteFd))
        return false;
    return true;
}
#endif

bool loadWithTargetMemory(TargetProcess& target,
                          int tid,
                          const ElfImage& payloadElf,
                          const std::string& entryName,
                          const std::array<std::uint64_t, 8>& entryArgs,
                          std::uint64_t imageBase,
                          std::int64_t& entryResult,
                          std::string& error) {
    error.clear();
    if (imageBase == 0 || payloadElf.imageSize == 0 || (imageBase & (kPageSize - 1)) != 0) {
        error = "invalid target image allocation";
        return false;
    }
    if (payloadElf.hasTls) {
        error = "custom target loader does not support PT_TLS payloads";
        return false;
    }
    std::vector<MemoryMap> maps;
    if (!readProcessMaps(target.identity().pid, maps, error))
        return false;
    ResolvedTargetSymbol dlopen, dlsym, dlerror;
    if (!resolveTargetSymbol(maps, "dlopen", dlopen, error) ||
        !resolveTargetSymbol(maps, "dlsym", dlsym, error) ||
        !resolveTargetSymbol(maps, "dlerror", dlerror, error))
        return false;
    ResolvedTargetSymbol getauxval;
    std::string auxError;
    const bool hasGetauxval = resolveTargetSymbol(maps, "getauxval", getauxval, auxError);
    ResolvedTargetSymbol dlvsym;
    std::string dlvsymError;
    const bool hasDlvsym = resolveTargetSymbol(maps, "dlvsym", dlvsym, dlvsymError);

    std::uint64_t loadBias = 0;
    if (imageBase < payloadElf.lowestPage) {
        error = "target image allocation is below ELF lowest page";
        return false;
    }
    loadBias = imageBase - payloadElf.lowestPage;
    if (payloadElf.memory.size() != payloadElf.imageSize ||
        !target.writeMemory(imageBase, payloadElf.memory.data(), payloadElf.memory.size())) {
        error = "failed to copy ELF image into target RWX allocation";
        std::string ignored;
        target.remoteMunmap(tid, imageBase, payloadElf.imageSize, ignored);
        return false;
    }

    std::uint64_t scratch = 0;
    if (!target.remoteMmap(tid, kScratchSize, scratch, error, PROT_READ | PROT_WRITE)) {
        std::string ignored;
        target.remoteMunmap(tid, imageBase, payloadElf.imageSize, ignored);
        return false;
    }
    std::map<std::uint32_t, std::size_t> parsedByType;
    std::map<std::uint32_t, std::size_t> appliedByType;
    std::size_t appliedRelr = 0;
    auto fail = [&](const std::string& message) {
        error = message;
        std::cerr << "state=custom-linker-relocations total=" << payloadElf.relocations.size()
                  << " relr=" << payloadElf.relativeRelocationCount
                  << " relr_applied=" << appliedRelr;
        for (const auto& [type, parsed] : parsedByType)
            std::cerr << " type=" << type << " parsed=" << parsed
                      << " applied=" << appliedByType[type];
        std::cerr << '\n';
        std::string ignored;
        target.remoteMunmap(tid, scratch, kScratchSize, ignored);
        target.remoteMunmap(tid, imageBase, payloadElf.imageSize, ignored);
        return false;
    };
    const std::uint64_t nameAddress = scratch;
    const std::uint64_t versionAddress = scratch + 4096;
    std::vector<std::pair<std::string, std::uint64_t>> dependencyHandles;
    auto callDlopen = [&](const std::string& name) -> bool {
        if (name.size() + 1 > 4096) {
            error = "dependency name exceeds remote scratch capacity: " + name;
            return false;
        }
        if (!target.writeMemory(nameAddress, name.c_str(), name.size() + 1)) {
            error = "failed to write dependency name: " + name;
            return false;
        }
        std::int64_t handle = 0;
        std::string callError;
        if (!target.remoteCall(tid, dlopen.address,
                               {nameAddress, kRtldNow | kRtldGlobal, 0, 0, 0, 0, 0, 0},
                               handle, callError) || handle == 0) {
            std::string detail;
            if (linkerError(target, dlerror, detail) && !detail.empty())
                error = detail;
            else
                error = callError.empty() ? "target dependency dlopen failed: " + name : callError;
            return false;
        }
        dependencyHandles.emplace_back(name, static_cast<std::uint64_t>(handle));
        return true;
    };
    for (const auto& dependency : payloadElf.neededLibraries) {
        if (!callDlopen(dependency))
            return fail(error);
    }

    std::uint64_t nextRelrOffset = 0;
    for (const auto encoded : payloadElf.relativeRelocations) {
        if ((encoded & 1u) == 0) {
            nextRelrOffset = encoded;
            if (nextRelrOffset > payloadElf.imageSize - sizeof(std::uint64_t))
                return fail("RELR offset is outside target image");
            const auto destination = loadBias + nextRelrOffset;
            std::uint64_t word = 0;
            if (!target.readMemory(destination, &word, sizeof(word)))
                return fail("failed to read RELR relocation");
            word += loadBias;
            if (!target.writeMemory(destination, &word, sizeof(word)))
                return fail("failed to apply RELR relocation");
            ++appliedRelr;
            if (nextRelrOffset > std::numeric_limits<std::uint64_t>::max() - sizeof(std::uint64_t))
                return fail("RELR offset overflow");
            nextRelrOffset += sizeof(std::uint64_t);
            continue;
        }
        const auto bitmap = encoded >> 1;
        for (std::size_t bit = 0; bit < 63; ++bit) {
            if ((bitmap & (std::uint64_t{1} << bit)) == 0)
                continue;
            const auto displacement = static_cast<std::uint64_t>(bit * sizeof(std::uint64_t));
            if (nextRelrOffset > payloadElf.imageSize - sizeof(std::uint64_t) - displacement)
                return fail("RELR bitmap points outside target image");
            const auto destination = loadBias + nextRelrOffset + displacement;
            std::uint64_t word = 0;
            if (!target.readMemory(destination, &word, sizeof(word)))
                return fail("failed to read RELR bitmap relocation");
            word += loadBias;
            if (!target.writeMemory(destination, &word, sizeof(word)))
                return fail("failed to apply RELR bitmap relocation");
            ++appliedRelr;
        }
        if (nextRelrOffset > payloadElf.imageSize - 63 * sizeof(std::uint64_t))
            return fail("RELR bitmap offset overflow");
        nextRelrOffset += 63 * sizeof(std::uint64_t);
    }

    std::vector<std::uint64_t> symbolAddresses(payloadElf.symbols.size(), 0);
    std::vector<bool> symbolResolved(payloadElf.symbols.size(), false);
    std::uint64_t targetHwcap = 0;
    if (hasGetauxval) {
        std::int64_t hwcapResult = 0;
        std::string hwcapError;
        if (target.remoteCall(tid, getauxval.address, {16, 0, 0, 0, 0, 0, 0, 0},
                               hwcapResult, hwcapError) && hwcapResult >= 0)
            targetHwcap = static_cast<std::uint64_t>(hwcapResult);
    }
    auto invokeIfunc = [&](std::uint64_t resolver, std::uint64_t& value) -> bool {
        std::int64_t resolved = 0;
        if (!target.remoteCall(tid, resolver,
                               {targetHwcap, 0, 0, 0, 0, 0, 0, 0},
                               resolved, error) || resolved == 0) {
            if (error.empty())
                error = "IFUNC resolver returned no address";
            return false;
        }
        value = static_cast<std::uint64_t>(resolved);
        return true;
    };
    auto resolveSymbol = [&](std::uint64_t index, std::uint64_t& value) -> bool {
        if (index >= payloadElf.symbols.size()) {
            error = "relocation symbol index is out of range";
            return false;
        }
        if (symbolResolved[static_cast<std::size_t>(index)]) {
            value = symbolAddresses[static_cast<std::size_t>(index)];
            return true;
        }
        const auto& symbol = payloadElf.symbols[static_cast<std::size_t>(index)];
        if (symbol.sectionIndex != 0) {
            if (symbol.sectionIndex != kShnAbs &&
                symbol.value > std::numeric_limits<std::uint64_t>::max() - loadBias) {
                error = "defined symbol address overflow";
                return false;
            }
            value = symbol.sectionIndex == kShnAbs ? symbol.value : loadBias + symbol.value;
            if ((symbol.info & 0x0f) == kSttGnuIfunc && !invokeIfunc(value, value))
                return false;
        } else {
            if (symbol.name.empty()) {
                value = 0;
            } else if (symbol.name.size() + 1 > 4096 ||
                       !target.writeMemory(nameAddress, symbol.name.c_str(), symbol.name.size() + 1)) {
                error = "failed to write undefined symbol name";
                return false;
            } else {
                std::int64_t resolved = 0;
                std::string callError;
                bool found = false;
                const bool needsVersion = !symbol.versionName.empty();
                if (needsVersion && !hasDlvsym) {
                    error = "versioned symbol requires target dlvsym: " + symbol.name;
                    return false;
                }
                if (needsVersion && (symbol.versionName.size() + 1 > 4096 ||
                                     !target.writeMemory(versionAddress, symbol.versionName.c_str(),
                                                         symbol.versionName.size() + 1))) {
                    error = "failed to write symbol version name";
                    return false;
                }
                const bool hasVersion = needsVersion;
                auto tryDependency = [&](const std::pair<std::string, std::uint64_t>& dependency) {
                    if (hasVersion) {
                        std::int64_t candidate = 0;
                        if (target.remoteCall(tid, dlvsym.address,
                            {dependency.second, nameAddress, versionAddress, 0, 0, 0, 0, 0},
                            candidate, callError) && candidate != 0) {
                            resolved = candidate;
                            return true;
                        }
                        return false;
                    }
                    std::int64_t candidate = 0;
                    if (target.remoteCall(tid, dlsym.address,
                        {dependency.second, nameAddress, 0, 0, 0, 0, 0, 0},
                        candidate, callError) && candidate != 0) {
                        resolved = candidate;
                        return true;
                    }
                    return false;
                };
                if (!symbol.versionLibrary.empty()) {
                    for (const auto& dependency : dependencyHandles) {
                        if (dependency.first == symbol.versionLibrary && tryDependency(dependency)) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) {
                    for (const auto& dependency : dependencyHandles) {
                        if (tryDependency(dependency)) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found && needsVersion) {
                    target.remoteCall(tid, dlvsym.address,
                        {0, nameAddress, versionAddress, 0, 0, 0, 0, 0},
                        resolved, callError);
                    found = resolved != 0;
                }
                if (!found && !needsVersion) {
                    target.remoteCall(tid, dlsym.address,
                        {0, nameAddress, 0, 0, 0, 0, 0, 0},
                        resolved, callError);
                    found = resolved != 0;
                }
                value = static_cast<std::uint64_t>(resolved);
                if (!found && (symbol.info >> 4) != 2) {
                    std::string detail;
                    if (linkerError(target, dlerror, detail) && !detail.empty())
                        error = detail;
                    else
                        error = "undefined symbol not found: " + symbol.name;
                    return false;
                }
            }
        }
        symbolAddresses[static_cast<std::size_t>(index)] = value;
        symbolResolved[static_cast<std::size_t>(index)] = true;
        return true;
    };

    for (const auto& relocation : payloadElf.relocations) {
        ++parsedByType[relocation.type];
        if (relocation.offset > std::numeric_limits<std::uint64_t>::max() - loadBias) 
            return fail("relocation address overflow");
        const std::uint64_t destination = loadBias + relocation.offset;
        std::uint64_t symbolValue = 0;
        std::uint64_t relocated = 0;
        switch (relocation.type) {
        case kRNone:
            ++appliedByType[relocation.type];
            continue;
        case kRRelative:
            if (!addSignedOffset(loadBias, relocation.addend, relocated))
                return fail("R_AARCH64_RELATIVE addend overflow");
            break;
        case kRIrelative: {
            std::uint64_t resolver = 0;
            if (!addSignedOffset(loadBias, relocation.addend, resolver))
                return fail("R_AARCH64_IRELATIVE addend overflow");
            if (!invokeIfunc(resolver, relocated))
                return fail(error);
            break;
        }
        case kRAbs64:
        case kRGlobDat:
        case kRJumpSlot:
            if (!resolveSymbol(relocation.symbolIndex, symbolValue))
                return fail(error);
            if (!addSignedOffset(symbolValue, relocation.addend, relocated))
                return fail("absolute relocation addend overflow");
            break;
        case kRPrel64:
            if (!resolveSymbol(relocation.symbolIndex, symbolValue))
                return fail(error);
            if (!calculateSignedRelative(symbolValue, relocation.addend, destination, 64, relocated))
                return fail("R_AARCH64_PREL64 value overflow");
            break;
        case kRAbs32: {
            if (!resolveSymbol(relocation.symbolIndex, symbolValue))
                return fail(error);
            std::uint64_t absolute = 0;
            if (!addSignedOffset(symbolValue, relocation.addend, absolute) || absolute > UINT32_MAX)
                return fail("R_AARCH64_ABS32 value overflow");
            const auto value32 = static_cast<std::uint32_t>(absolute);
            if (!target.writeMemory(destination, &value32, sizeof(value32)))
                return fail("failed to write R_AARCH64_ABS32 relocation");
            ++appliedByType[relocation.type];
            continue;
        }
        case kRAbs16: {
            if (!resolveSymbol(relocation.symbolIndex, symbolValue))
                return fail(error);
            std::uint64_t absolute = 0;
            if (!addSignedOffset(symbolValue, relocation.addend, absolute) || absolute > UINT16_MAX)
                return fail("R_AARCH64_ABS16 value overflow");
            const auto value16 = static_cast<std::uint16_t>(absolute);
            if (!target.writeMemory(destination, &value16, sizeof(value16)))
                return fail("failed to write R_AARCH64_ABS16 relocation");
            ++appliedByType[relocation.type];
            continue;
        }
        case kRPrel32: {
            if (!resolveSymbol(relocation.symbolIndex, symbolValue))
                return fail(error);
            std::uint64_t relative = 0;
            if (!calculateSignedRelative(symbolValue, relocation.addend, destination, 32, relative))
                return fail("R_AARCH64_PREL32 value overflow");
            const auto value32 = static_cast<std::uint32_t>(relative);
            if (!target.writeMemory(destination, &value32, sizeof(value32)))
                return fail("failed to write R_AARCH64_PREL32 relocation");
            ++appliedByType[relocation.type];
            continue;
        }
        case kRPrel16: {
            if (!resolveSymbol(relocation.symbolIndex, symbolValue))
                return fail(error);
            std::uint64_t relative = 0;
            if (!calculateSignedRelative(symbolValue, relocation.addend, destination, 16, relative))
                return fail("R_AARCH64_PREL16 value overflow");
            const auto value16 = static_cast<std::uint16_t>(relative);
            if (!target.writeMemory(destination, &value16, sizeof(value16)))
                return fail("failed to write R_AARCH64_PREL16 relocation");
            ++appliedByType[relocation.type];
            continue;
        }
        default:
            return fail("unsupported AArch64 relocation type " + std::to_string(relocation.type));
        }
        if (!target.writeMemory(destination, &relocated, sizeof(relocated)))
            return fail("failed to write relocation at target address");
        ++appliedByType[relocation.type];
    }

    std::cerr << "state=custom-linker-relocations total=" << payloadElf.relocations.size()
              << " relr=" << payloadElf.relativeRelocationCount
              << " relr_applied=" << appliedRelr
              << " dependencies=" << dependencyHandles.size()
              << " init=" << (payloadElf.initFunction != 0 ? 1 : 0)
              << " init_array=" << payloadElf.initArrayCount;
    for (const auto& [type, parsed] : parsedByType)
        std::cerr << " type=" << type << " parsed=" << parsed
                  << " applied=" << appliedByType[type];
    std::cerr << '\n';

    if (payloadElf.initFunction != 0) {
        std::int64_t ignoredResult = 0;
        if (!target.remoteCall(tid, loadBias + payloadElf.initFunction, {}, ignoredResult, error))
            return fail("payload DT_INIT call failed: " + error);
    }
    for (std::uint64_t i = 0; i < payloadElf.initArrayCount; ++i) {
        std::uint64_t initializer = 0;
        if (!target.readMemory(loadBias + payloadElf.initArrayAddress + i * sizeof(initializer),
                               &initializer, sizeof(initializer)))
            return fail("failed to read payload initializer address");
        if (initializer == 0 || initializer == std::numeric_limits<std::uint64_t>::max())
            continue;
        std::int64_t ignoredResult = 0;
        if (!target.remoteCall(tid, initializer, {}, ignoredResult, error))
            return fail("payload DT_INIT_ARRAY call failed: " + error);
    }

    const auto entry = std::find_if(payloadElf.symbols.begin(), payloadElf.symbols.end(),
        [&](const DynamicSymbol& symbol) {
            const auto binding = symbol.info >> 4;
            const auto type = symbol.info & 0x0f;
            return symbol.name == entryName && symbol.sectionIndex != 0 &&
                   (binding == 1 || binding == 2) &&
                   (type == 2 || type == kSttGnuIfunc);
        });
    if (entry == payloadElf.symbols.end())
        return fail("payload entry symbol not found: " + entryName);
    if (entry->sectionIndex != kShnAbs &&
        entry->value > std::numeric_limits<std::uint64_t>::max() - loadBias)
        return fail("payload entry address overflow");
    std::uint64_t entryAddress = entry->sectionIndex == kShnAbs ? entry->value : loadBias + entry->value;
    if ((entry->info & 0x0f) == kSttGnuIfunc && !invokeIfunc(entryAddress, entryAddress))
        return fail(error);
    if (!target.remoteCall(tid, entryAddress, entryArgs, entryResult, error))
        return fail("payload entry call failed: " + error);

    std::string cleanupError;
    if (!target.remoteMunmap(tid, scratch, kScratchSize, cleanupError))
        return fail(cleanupError);
    return true;
}

} // namespace injector
