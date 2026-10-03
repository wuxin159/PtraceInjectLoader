#include "elf_image.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <utility>

namespace injector {
namespace {

constexpr std::uint16_t kEtDyn = 3;
constexpr std::uint16_t kMachineAArch64 = 183;
constexpr std::uint32_t kPtLoad = 1;
constexpr std::uint32_t kPtDynamic = 2;
constexpr std::uint32_t kPtNote = 4;
constexpr std::uint32_t kPtPhdr = 6;
constexpr std::uint32_t kPtTls = 7;
constexpr std::uint32_t kPtGnuEhFrame = 0x6474e550;
constexpr std::uint32_t kPtGnuStack = 0x6474e551;
constexpr std::uint32_t kPtGnuRelro = 0x6474e552;
constexpr std::uint32_t kPtGnuProperty = 0x6474e553;
constexpr std::uint64_t kPageSize = 4096;
constexpr std::uint64_t kDtNull = 0;
constexpr std::uint64_t kDtNeeded = 1;
constexpr std::uint64_t kDtPltRelSz = 2;
constexpr std::uint64_t kDtHash = 4;
constexpr std::uint64_t kDtStrtab = 5;
constexpr std::uint64_t kDtSymtab = 6;
constexpr std::uint64_t kDtRela = 7;
constexpr std::uint64_t kDtJmprel = 23;
constexpr std::uint64_t kDtStrsz = 10;
constexpr std::uint64_t kDtSyment = 11;
constexpr std::uint64_t kDtPltRel = 20;
constexpr std::uint64_t kDtRelaent = 9;
constexpr std::uint64_t kDtRelasz = 8;
constexpr std::uint64_t kDtRelaszTag = 18;
constexpr std::uint64_t kDtRelr = 36;
constexpr std::uint64_t kDtRelrsz = 35;
constexpr std::uint64_t kDtRelrent = 37;
constexpr std::uint64_t kDtInitArraysz = 27;
constexpr std::uint64_t kDtInitArray = 25;
constexpr std::uint64_t kDtInit = 12;
constexpr std::uint64_t kDtSoname = 14;
constexpr std::uint64_t kDtTextRel = 22;
constexpr std::uint64_t kDtFlags = 30;
constexpr std::uint64_t kDtGnuHash = 0x6ffffef5;
constexpr std::uint64_t kDtVersym = 0x6ffffff0;
constexpr std::uint64_t kDtVerdef = 0x6ffffffc;
constexpr std::uint64_t kDtVerdefNum = 0x6ffffffd;
constexpr std::uint64_t kDtVerneed = 0x6ffffffe;
constexpr std::uint64_t kDtVerneedNum = 0x6fffffff;
constexpr std::uint32_t kRNone = 0;
constexpr std::uint32_t kRAbs32 = 258;
constexpr std::uint32_t kRAbs16 = 259;
constexpr std::uint32_t kRPrel32 = 261;
constexpr std::uint32_t kRPrel16 = 262;

struct ProgramHeader {
    std::uint32_t type;
    std::uint32_t flags;
    std::uint64_t offset;
    std::uint64_t virtualAddress;
    std::uint64_t physicalAddress;
    std::uint64_t fileSize;
    std::uint64_t memorySize;
    std::uint64_t alignment;
};

struct DynamicEntry {
    std::int64_t tag;
    std::uint64_t value;
};

struct SymbolEntry {
    std::uint32_t name;
    std::uint8_t info;
    std::uint8_t other;
    std::uint16_t sectionIndex;
    std::uint64_t value;
    std::uint64_t size;
};

struct RelaEntry {
    std::uint64_t offset;
    std::uint64_t info;
    std::int64_t addend;
};

struct VersionNeed {
    std::uint16_t version;
    std::uint16_t count;
    std::uint32_t file;
    std::uint32_t auxiliary;
    std::uint32_t next;
};

struct VersionNeedAux {
    std::uint32_t hash;
    std::uint16_t flags;
    std::uint16_t other;
    std::uint32_t name;
    std::uint32_t next;
};

struct VersionDef {
    std::uint16_t version;
    std::uint16_t flags;
    std::uint16_t index;
    std::uint16_t count;
    std::uint32_t hash;
    std::uint32_t auxiliary;
    std::uint32_t next;
};

struct VersionDefAux {
    std::uint32_t name;
    std::uint32_t next;
};

template <typename T>
bool readAt(const std::vector<std::uint8_t>& bytes, std::uint64_t offset, T& value) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - static_cast<std::size_t>(offset))
        return false;
    std::memcpy(&value, bytes.data() + static_cast<std::size_t>(offset), sizeof(T));
    return true;
}

bool addOverflows(std::uint64_t a, std::uint64_t b) {
    return b > std::numeric_limits<std::uint64_t>::max() - a;
}

bool multiplyOverflows(std::uint64_t a, std::uint64_t b) {
    return a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a;
}

bool alignDown(std::uint64_t value, std::uint64_t alignment, std::uint64_t& result) {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0)
        return false;
    result = value & ~(alignment - 1);
    return true;
}

bool alignUp(std::uint64_t value, std::uint64_t alignment, std::uint64_t& result) {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
        addOverflows(value, alignment - 1))
        return false;
    result = (value + alignment - 1) & ~(alignment - 1);
    return true;
}

bool virtualToFile(const std::vector<LoadSegment>& segments,
                   std::uint64_t address,
                   std::uint64_t size,
                   std::uint64_t& fileOffset) {
    for (const auto& segment : segments) {
        if (address < segment.virtualAddress)
            continue;
        const auto delta = address - segment.virtualAddress;
        if (delta <= segment.fileSize && size <= segment.fileSize - delta &&
            !addOverflows(segment.fileOffset, delta)) {
            fileOffset = segment.fileOffset + delta;
            return true;
        }
    }
    return false;
}

bool virtualRangeInMemory(const std::vector<LoadSegment>& segments,
                          std::uint64_t address,
                          std::uint64_t size) {
    if (addOverflows(address, size))
        return false;
    for (const auto& segment : segments) {
        if (address < segment.virtualAddress)
            continue;
        const auto delta = address - segment.virtualAddress;
        if (delta <= segment.memorySize && size <= segment.memorySize - delta)
            return true;
    }
    return false;
}

std::size_t relocationWidth(std::uint32_t type) {
    switch (type) {
    case kRNone: return 0;
    case kRAbs16:
    case kRPrel16: return sizeof(std::uint16_t);
    case kRAbs32:
    case kRPrel32: return sizeof(std::uint32_t);
    default: return sizeof(std::uint64_t);
    }
}

bool tableSymbolCount(const std::vector<std::uint8_t>& file,
                      const std::vector<LoadSegment>& segments,
                      std::uint64_t hashAddress,
                      bool gnuHash,
                      std::uint64_t& count) {
    std::uint64_t offset = 0;
    if (!virtualToFile(segments, hashAddress, 8, offset))
        return false;
    std::uint32_t first = 0, second = 0;
    if (!readAt(file, offset, first) || !readAt(file, offset + 4, second))
        return false;
    if (!gnuHash) {
        count = second;
        return count != 0 && count <= (1u << 20);
    }
    const std::uint32_t bucketCount = first;
    const std::uint32_t symbolOffset = second;
    std::uint32_t bloomCount = 0;
    if (!readAt(file, offset + 8, bloomCount) || bucketCount == 0 || bloomCount == 0 ||
        bucketCount > (1u << 20) || bloomCount > (1u << 20))
        return false;
    const std::uint64_t bloomBytes = static_cast<std::uint64_t>(bloomCount) * 8;
    const std::uint64_t bucketBytes = static_cast<std::uint64_t>(bucketCount) * 4;
    if (addOverflows(offset + 16, bloomBytes) || addOverflows(offset + 16 + bloomBytes, bucketBytes))
        return false;
    const std::uint64_t bucketsOffset = offset + 16 + bloomBytes;
    std::uint32_t highestBucket = 0;
    for (std::uint32_t i = 0; i < bucketCount; ++i) {
        std::uint32_t bucket = 0;
        if (!readAt(file, bucketsOffset + static_cast<std::uint64_t>(i) * 4, bucket))
            return false;
        highestBucket = std::max(highestBucket, bucket);
    }
    if (highestBucket < symbolOffset) {
        count = symbolOffset;
        return count != 0;
    }
    const std::uint64_t chainsOffset = bucketsOffset + bucketBytes;
    for (std::uint64_t symbol = highestBucket, traversed = 0; traversed < (1u << 20); ++symbol, ++traversed) {
        std::uint32_t chain = 0;
        if (!readAt(file, chainsOffset + (symbol - symbolOffset) * 4, chain))
            return false;
        if (chain & 1) {
            count = symbol + 1;
            return count <= (1u << 20);
        }
    }
    return false;
}

bool appendRelaTable(const std::vector<std::uint8_t>& file,
                     const std::vector<LoadSegment>& segments,
                     std::uint64_t address,
                     std::uint64_t size,
                     std::vector<DynamicRelocation>& output) {
    if (size % sizeof(RelaEntry) != 0)
        return false;
    std::uint64_t offset = 0;
    if (size != 0 && !virtualToFile(segments, address, size, offset))
        return false;
    for (std::uint64_t cursor = 0; cursor < size; cursor += sizeof(RelaEntry)) {
        RelaEntry rela{};
        if (!readAt(file, offset + cursor, rela))
            return false;
        output.push_back({rela.offset, rela.info >> 32,
                          static_cast<std::uint32_t>(rela.info), rela.addend});
    }
    return true;
}

bool appendRelrTable(const std::vector<std::uint8_t>& file,
                     const std::vector<LoadSegment>& segments,
                     std::uint64_t address,
                     std::uint64_t size,
                     std::uint64_t entrySize,
                     std::vector<std::uint64_t>& output) {
    if (entrySize != sizeof(std::uint64_t) || size % entrySize != 0)
        return false;
    std::uint64_t offset = 0;
    if (size != 0 && !virtualToFile(segments, address, size, offset))
        return false;
    for (std::uint64_t cursor = 0; cursor < size; cursor += entrySize) {
        std::uint64_t entry = 0;
        if (!readAt(file, offset + cursor, entry))
            return false;
        output.push_back(entry);
    }
    return true;
}

bool readDynamicString(const std::vector<std::uint8_t>& file,
                       std::uint64_t stringOffset,
                       std::uint64_t stringTableSize,
                       std::uint32_t nameOffset,
                       std::string& value) {
    if (nameOffset >= stringTableSize || addOverflows(stringOffset, stringTableSize))
        return false;
    const auto begin = file.begin() + static_cast<std::ptrdiff_t>(stringOffset + nameOffset);
    const auto end = file.begin() + static_cast<std::ptrdiff_t>(stringOffset + stringTableSize);
    const auto terminator = std::find(begin, end, 0);
    if (terminator == end)
        return false;
    value.assign(begin, terminator);
    return true;
}

} // namespace

bool parseElfImage(const std::vector<std::uint8_t>& file,
                   std::uint64_t maxImageSize,
                   ElfImage& image,
                   std::string& error) {
    image = {};
    error.clear();
    if (file.size() < 64 || file[0] != 0x7f || file[1] != 'E' ||
        file[2] != 'L' || file[3] != 'F' || file[4] != 2 || file[5] != 1 || file[6] != 1) {
        error = "expected little-endian ELF64";
        return false;
    }

    std::uint16_t type = 0, machine = 0, headerSize = 0, programHeaderSize = 0, programHeaderCount = 0;
    std::uint64_t programHeaderOffset = 0;
    if (!readAt(file, 16, type) || !readAt(file, 18, machine) ||
        !readAt(file, 32, programHeaderOffset) || !readAt(file, 52, headerSize) ||
        !readAt(file, 54, programHeaderSize) || !readAt(file, 56, programHeaderCount) ||
        type != kEtDyn || machine != kMachineAArch64 || headerSize != 64 || programHeaderSize != 56) {
        error = "invalid ELF header: expected AArch64 ET_DYN with standard ELF64 headers";
        return false;
    }
    if (programHeaderCount == 0 || multiplyOverflows(programHeaderSize, programHeaderCount) ||
        addOverflows(programHeaderOffset, static_cast<std::uint64_t>(programHeaderSize) * programHeaderCount) ||
        programHeaderOffset + static_cast<std::uint64_t>(programHeaderSize) * programHeaderCount > file.size()) {
        error = "program header table is out of bounds";
        return false;
    }

    std::vector<ProgramHeader> dynamicHeaders;
    std::uint64_t highestAddress = 0;
    std::uint64_t lowestAddress = std::numeric_limits<std::uint64_t>::max();
    for (std::uint16_t i = 0; i < programHeaderCount; ++i) {
        ProgramHeader ph{};
        const auto offset = programHeaderOffset + static_cast<std::uint64_t>(i) * programHeaderSize;
        if (!readAt(file, offset, ph.type) || !readAt(file, offset + 4, ph.flags) ||
            !readAt(file, offset + 8, ph.offset) || !readAt(file, offset + 16, ph.virtualAddress) ||
            !readAt(file, offset + 24, ph.physicalAddress) || !readAt(file, offset + 32, ph.fileSize) ||
            !readAt(file, offset + 40, ph.memorySize) || !readAt(file, offset + 48, ph.alignment)) {
            error = "truncated program header";
            return false;
        }
        if (ph.type == kPtTls)
            image.hasTls = true;
        if (ph.type == kPtDynamic)
            dynamicHeaders.push_back(ph);
        if (ph.type != 0 && ph.type != kPtLoad && ph.type != kPtDynamic && ph.type != kPtNote &&
            ph.type != kPtPhdr && ph.type != kPtTls && ph.type != kPtGnuEhFrame &&
            ph.type != kPtGnuStack && ph.type != kPtGnuRelro && ph.type != kPtGnuProperty) {
            error = "unsupported program header type " + std::to_string(ph.type);
            return false;
        }
        if (ph.type != kPtLoad)
            continue;
        if (ph.fileSize > ph.memorySize || addOverflows(ph.offset, ph.fileSize) ||
            ph.offset + ph.fileSize > file.size() || addOverflows(ph.virtualAddress, ph.memorySize) ||
            ph.memorySize == 0 || (ph.alignment > 1 &&
            ((ph.alignment & (ph.alignment - 1)) != 0 ||
             (ph.virtualAddress % ph.alignment) != (ph.offset % ph.alignment)))) {
            error = "invalid PT_LOAD range or alignment";
            return false;
        }
        std::uint64_t segmentEnd = 0;
        if (!alignUp(ph.virtualAddress + ph.memorySize, kPageSize, segmentEnd)) {
            error = "PT_LOAD range overflows page alignment";
            return false;
        }
        lowestAddress = std::min(lowestAddress, ph.virtualAddress);
        highestAddress = std::max(highestAddress, segmentEnd);
        image.segments.push_back({ph.virtualAddress, ph.offset, ph.fileSize, ph.memorySize, ph.flags, ph.alignment});
    }

    if (dynamicHeaders.size() > 1) {
        error = "ELF contains multiple PT_DYNAMIC segments";
        return false;
    }
    if (image.segments.empty() || !alignDown(lowestAddress, kPageSize, image.lowestPage) ||
        highestAddress < image.lowestPage) {
        error = "ELF has no usable PT_LOAD image";
        return false;
    }
    image.imageSize = highestAddress - image.lowestPage;
    if (image.imageSize == 0 || image.imageSize > maxImageSize ||
        image.imageSize > std::numeric_limits<std::size_t>::max()) {
        error = "ELF image exceeds configured size limit";
        return false;
    }

    auto sorted = image.segments;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.virtualAddress < b.virtualAddress;
    });
    for (std::size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i - 1].virtualAddress + sorted[i - 1].memorySize > sorted[i].virtualAddress) {
            error = "overlapping PT_LOAD memory ranges are unsupported";
            return false;
        }
    }

    image.memory.assign(static_cast<std::size_t>(image.imageSize), 0);
    for (const auto& segment : image.segments) {
        const auto destination = segment.virtualAddress - image.lowestPage;
        if (destination > image.memory.size() || segment.fileSize > image.memory.size() - destination) {
            error = "PT_LOAD does not fit in computed image";
            image = {};
            return false;
        }
        std::memcpy(image.memory.data() + static_cast<std::size_t>(destination),
                    file.data() + static_cast<std::size_t>(segment.fileOffset),
                    static_cast<std::size_t>(segment.fileSize));
    }

    for (const auto& dynamic : dynamicHeaders) {
        if (dynamic.fileSize % sizeof(DynamicEntry) != 0 || addOverflows(dynamic.offset, dynamic.fileSize) ||
            dynamic.offset + dynamic.fileSize > file.size()) {
            error = "invalid PT_DYNAMIC table";
            image = {};
            return false;
        }
        std::uint64_t stringTable = 0, stringTableSize = 0, relaAddress = 0, relaSize = 0;
        std::uint64_t pltAddress = 0, pltSize = 0, pltType = 0, relaEntrySize = 0;
        std::uint64_t relrAddress = 0, relrSize = 0, relrEntrySize = sizeof(std::uint64_t);
        std::uint64_t symbolTable = 0, symbolEntrySize = 0, sysvHash = 0, gnuHash = 0;
        std::uint64_t relSize = 0, initArraySize = 0, sonameOffset = std::numeric_limits<std::uint64_t>::max();
        std::uint64_t versionSymbols = 0, versionNeed = 0, versionNeedCount = 0;
        std::uint64_t versionDef = 0, versionDefCount = 0;
        std::vector<std::uint64_t> neededOffsets;
        bool terminated = false;
        bool hasTextRel = false;
        for (std::uint64_t offset = 0; offset < dynamic.fileSize; offset += sizeof(DynamicEntry)) {
            DynamicEntry entry{};
            if (!readAt(file, dynamic.offset + offset, entry)) {
                error = "truncated PT_DYNAMIC entry";
                image = {};
                return false;
            }
            if (entry.tag == static_cast<std::int64_t>(kDtNull)) {
                terminated = true;
                break;
            }
            switch (entry.tag) {
                case static_cast<std::int64_t>(kDtNeeded): neededOffsets.push_back(entry.value); break;
                case static_cast<std::int64_t>(kDtStrtab): stringTable = entry.value; break;
                case static_cast<std::int64_t>(kDtStrsz): stringTableSize = entry.value; break;
                case static_cast<std::int64_t>(kDtRela): relaAddress = entry.value; break;
                case static_cast<std::int64_t>(kDtRelasz): relaSize = entry.value; break;
                case static_cast<std::int64_t>(kDtRelaent): relaEntrySize = entry.value; break;
                case static_cast<std::int64_t>(kDtRelr): relrAddress = entry.value; break;
                case static_cast<std::int64_t>(kDtRelrsz): relrSize = entry.value; break;
                case static_cast<std::int64_t>(kDtRelrent): relrEntrySize = entry.value; break;
                case static_cast<std::int64_t>(kDtJmprel): pltAddress = entry.value; break;
                case static_cast<std::int64_t>(kDtPltRelSz): pltSize = entry.value; break;
                case static_cast<std::int64_t>(kDtPltRel): pltType = entry.value; break;
                case static_cast<std::int64_t>(kDtSymtab): symbolTable = entry.value; break;
                case static_cast<std::int64_t>(kDtSyment): symbolEntrySize = entry.value; break;
                case static_cast<std::int64_t>(kDtHash): sysvHash = entry.value; break;
                case static_cast<std::int64_t>(kDtGnuHash): gnuHash = entry.value; break;
                case static_cast<std::int64_t>(kDtRelaszTag): relSize = entry.value; break;
                case static_cast<std::int64_t>(kDtInitArraysz): initArraySize = entry.value; break;
                case static_cast<std::int64_t>(kDtInitArray): image.initArrayAddress = entry.value; break;
                case static_cast<std::int64_t>(kDtInit): image.initFunction = entry.value; break;
                case static_cast<std::int64_t>(kDtSoname): sonameOffset = entry.value; break;
                case static_cast<std::int64_t>(kDtTextRel): hasTextRel = true; break;
                case static_cast<std::int64_t>(kDtFlags): hasTextRel = hasTextRel || (entry.value & 4) != 0; break;
                case static_cast<std::int64_t>(kDtVersym): versionSymbols = entry.value; break;
                case static_cast<std::int64_t>(kDtVerneed): versionNeed = entry.value; break;
                case static_cast<std::int64_t>(kDtVerneedNum): versionNeedCount = entry.value; break;
                case static_cast<std::int64_t>(kDtVerdef): versionDef = entry.value; break;
                case static_cast<std::int64_t>(kDtVerdefNum): versionDefCount = entry.value; break;
                default: break;
            }
        }
        if (!terminated) {
            error = "PT_DYNAMIC has no DT_NULL terminator";
            image = {};
            return false;
        }
        if (hasTextRel) {
            error = "text relocations are unsupported";
            image = {};
            return false;
        }
        if (relaSize != 0 && relaEntrySize != sizeof(RelaEntry)) {
            error = "unsupported DT_RELAENT size";
            image = {};
            return false;
        }
        if (relrSize != 0 && (relrEntrySize != sizeof(std::uint64_t) ||
                              !appendRelrTable(file, image.segments, relrAddress, relrSize,
                                               relrEntrySize, image.relativeRelocations))) {
            error = "RELR table is malformed or outside PT_LOAD file data";
            image = {};
            return false;
        }
        image.relativeRelocationCount = image.relativeRelocations.size();
        if (pltSize != 0 && pltType != kDtRela) {
            error = "PLT relocation table is not RELA";
            image = {};
            return false;
        }
        if (relSize != 0 || initArraySize % 8 != 0) {
            error = relSize != 0 ? "DT_REL relocations are unsupported" : "mis-sized initializer table";
            image = {};
            return false;
        }
        image.relocationCount += relaSize / sizeof(RelaEntry) + pltSize / sizeof(RelaEntry);
        image.initArrayCount += initArraySize / 8;
        std::uint64_t initFileOffset = 0;
        if ((image.initFunction != 0 && !virtualToFile(image.segments, image.initFunction, 1, initFileOffset)) ||
            (initArraySize != 0 && !virtualToFile(image.segments, image.initArrayAddress, initArraySize, initFileOffset))) {
            error = "initializer table or DT_INIT points outside file-backed PT_LOAD data";
            image = {};
            return false;
        }
        if (!neededOffsets.empty() || sonameOffset != std::numeric_limits<std::uint64_t>::max()) {
            std::uint64_t stringOffset = 0;
            if (stringTableSize == 0 || !virtualToFile(image.segments, stringTable, stringTableSize, stringOffset)) {
                error = "DT_STRTAB is not backed by file data";
                image = {};
                return false;
            }
            for (const auto nameOffset : neededOffsets) {
                if (nameOffset >= stringTableSize) {
                    error = "DT_NEEDED string offset is out of bounds";
                    image = {};
                    return false;
                }
                const auto begin = file.begin() + static_cast<std::ptrdiff_t>(stringOffset + nameOffset);
                const auto end = file.begin() + static_cast<std::ptrdiff_t>(stringOffset + stringTableSize);
                const auto terminator = std::find(begin, end, 0);
                if (terminator == end) {
                    error = "unterminated DT_NEEDED string";
                    image = {};
                    return false;
                }
                image.neededLibraries.emplace_back(begin, terminator);
            }
            if (sonameOffset != std::numeric_limits<std::uint64_t>::max()) {
                if (sonameOffset >= stringTableSize) {
                    error = "DT_SONAME string offset is out of bounds";
                    image = {};
                    return false;
                }
                const auto begin = file.begin() + static_cast<std::ptrdiff_t>(stringOffset + sonameOffset);
                const auto end = file.begin() + static_cast<std::ptrdiff_t>(stringOffset + stringTableSize);
                const auto terminator = std::find(begin, end, 0);
                if (terminator == end) {
                    error = "unterminated DT_SONAME string";
                    image = {};
                    return false;
                }
                image.soname.assign(begin, terminator);
            }
        }
        if (symbolTable != 0 || relaSize != 0 || pltSize != 0) {
            if (symbolTable == 0 || symbolEntrySize != sizeof(SymbolEntry) || stringTableSize == 0 ||
                (sysvHash == 0 && gnuHash == 0)) {
                error = "dynamic symbol table is missing required metadata or hash table";
                image = {};
                return false;
            }
            std::uint64_t symbolCount = 0;
            const bool hashValid = sysvHash != 0
                ? tableSymbolCount(file, image.segments, sysvHash, false, symbolCount)
                : tableSymbolCount(file, image.segments, gnuHash, true, symbolCount);
            std::uint64_t symbolOffset = 0, stringsOffset = 0;
            if (!hashValid || symbolCount == 0 || multiplyOverflows(symbolCount, symbolEntrySize) ||
                !virtualToFile(image.segments, symbolTable, symbolCount * symbolEntrySize, symbolOffset) ||
                !virtualToFile(image.segments, stringTable, stringTableSize, stringsOffset)) {
                error = "dynamic symbol or string table is out of bounds";
                image = {};
                return false;
            }
            image.symbols.reserve(static_cast<std::size_t>(symbolCount));
            for (std::uint64_t i = 0; i < symbolCount; ++i) {
                SymbolEntry symbol{};
                if (!readAt(file, symbolOffset + i * symbolEntrySize, symbol) || symbol.name >= stringTableSize) {
                    error = "invalid dynamic symbol entry";
                    image = {};
                    return false;
                }
                const auto begin = file.begin() + static_cast<std::ptrdiff_t>(stringsOffset + symbol.name);
                const auto end = file.begin() + static_cast<std::ptrdiff_t>(stringsOffset + stringTableSize);
                const auto terminator = std::find(begin, end, 0);
                if (terminator == end) {
                    error = "unterminated dynamic symbol name";
                    image = {};
                    return false;
                }
                DynamicSymbol parsedSymbol;
                parsedSymbol.name = std::string(begin, terminator);
                parsedSymbol.value = symbol.value;
                parsedSymbol.size = symbol.size;
                parsedSymbol.info = symbol.info;
                parsedSymbol.other = symbol.other;
                parsedSymbol.sectionIndex = symbol.sectionIndex;
                image.symbols.push_back(std::move(parsedSymbol));
            }
            std::map<std::uint16_t, std::pair<std::string, std::string>> requiredVersions;
            std::map<std::uint16_t, std::string> definedVersions;
            if (versionNeedCount > 65535 || versionDefCount > 65535) {
                error = "version table count exceeds limit";
                image = {};
                return false;
            }
            std::uint64_t needAddress = versionNeed;
            for (std::uint64_t i = 0; i < versionNeedCount; ++i) {
                std::uint64_t needOffset = 0;
                VersionNeed need{};
                if (!virtualToFile(image.segments, needAddress, sizeof(need), needOffset) ||
                    !readAt(file, needOffset, need) || need.count > 65535) {
                    error = "malformed DT_VERNEED table";
                    image = {};
                    return false;
                }
                std::string library;
                if (!readDynamicString(file, stringsOffset, stringTableSize, need.file, library)) {
                    error = "invalid DT_VERNEED library name";
                    image = {};
                    return false;
                }
                std::uint64_t auxiliaryAddress = needAddress + need.auxiliary;
                for (std::uint16_t j = 0; j < need.count; ++j) {
                    std::uint64_t auxOffset = 0;
                    VersionNeedAux auxiliary{};
                    if (!virtualToFile(image.segments, auxiliaryAddress, sizeof(auxiliary), auxOffset) ||
                        !readAt(file, auxOffset, auxiliary)) {
                        error = "malformed DT_VERNEED auxiliary table";
                        image = {};
                        return false;
                    }
                    std::string name;
                    if (!readDynamicString(file, stringsOffset, stringTableSize, auxiliary.name, name)) {
                        error = "invalid required symbol version name";
                        image = {};
                        return false;
                    }
                    requiredVersions[auxiliary.other & 0x7fff] = {std::move(name), library};
                    if (j + 1 < need.count) {
                        if (auxiliary.next == 0 || addOverflows(auxiliaryAddress, auxiliary.next)) {
                            error = "broken DT_VERNEED auxiliary chain";
                            image = {};
                            return false;
                        }
                        auxiliaryAddress += auxiliary.next;
                    }
                }
                if (i + 1 < versionNeedCount) {
                    if (need.next == 0 || addOverflows(needAddress, need.next)) {
                        error = "broken DT_VERNEED chain";
                        image = {};
                        return false;
                    }
                    needAddress += need.next;
                }
            }
            std::uint64_t defAddress = versionDef;
            for (std::uint64_t i = 0; i < versionDefCount; ++i) {
                std::uint64_t defOffset = 0;
                VersionDef definition{};
                if (!virtualToFile(image.segments, defAddress, sizeof(definition), defOffset) ||
                    !readAt(file, defOffset, definition) || definition.count == 0) {
                    error = "malformed DT_VERDEF table";
                    image = {};
                    return false;
                }
                std::uint64_t auxiliaryOffset = 0;
                VersionDefAux auxiliary{};
                if (!virtualToFile(image.segments, defAddress + definition.auxiliary,
                                   sizeof(auxiliary), auxiliaryOffset) ||
                    !readAt(file, auxiliaryOffset, auxiliary)) {
                    error = "malformed DT_VERDEF auxiliary table";
                    image = {};
                    return false;
                }
                std::string name;
                if (!readDynamicString(file, stringsOffset, stringTableSize, auxiliary.name, name)) {
                    error = "invalid defined symbol version name";
                    image = {};
                    return false;
                }
                definedVersions[definition.index & 0x7fff] = std::move(name);
                if (i + 1 < versionDefCount) {
                    if (definition.next == 0 || addOverflows(defAddress, definition.next)) {
                        error = "broken DT_VERDEF chain";
                        image = {};
                        return false;
                    }
                    defAddress += definition.next;
                }
            }
            if (versionSymbols != 0) {
                std::uint64_t versionOffset = 0;
                if (multiplyOverflows(symbolCount, sizeof(std::uint16_t)) ||
                    !virtualToFile(image.segments, versionSymbols,
                                   symbolCount * sizeof(std::uint16_t), versionOffset)) {
                    error = "DT_VERSYM table is out of bounds";
                    image = {};
                    return false;
                }
                for (std::uint64_t i = 0; i < symbolCount; ++i) {
                    std::uint16_t version = 0;
                    if (!readAt(file, versionOffset + i * sizeof(version), version)) {
                        error = "truncated DT_VERSYM table";
                        image = {};
                        return false;
                    }
                    auto& symbol = image.symbols[static_cast<std::size_t>(i)];
                    symbol.versionIndex = version & 0x7fff;
                    symbol.versionHidden = (version & 0x8000) != 0;
                    if (symbol.versionIndex <= 1)
                        continue;
                    if (symbol.sectionIndex == 0) {
                        const auto required = requiredVersions.find(symbol.versionIndex);
                        if (required == requiredVersions.end()) {
                            error = "missing version requirement for symbol " + symbol.name;
                            image = {};
                            return false;
                        }
                        symbol.versionName = required->second.first;
                        symbol.versionLibrary = required->second.second;
                    } else {
                        const auto defined = definedVersions.find(symbol.versionIndex);
                        if (defined != definedVersions.end())
                            symbol.versionName = defined->second;
                    }
                }
            }
            if (!appendRelaTable(file, image.segments, relaAddress, relaSize, image.relocations) ||
                !appendRelaTable(file, image.segments, pltAddress, pltSize, image.relocations)) {
                error = "RELA table is malformed or outside PT_LOAD file data";
                image = {};
                return false;
            }
            for (const auto& relocation : image.relocations) {
                const auto width = relocationWidth(relocation.type);
                if (relocation.symbolIndex >= image.symbols.size() ||
                    (width != 0 && !virtualRangeInMemory(image.segments, relocation.offset, width)) ||
                    relocation.offset < image.lowestPage ||
                    (width != 0 && (relocation.offset - image.lowestPage > image.memory.size() ||
                                    width > image.memory.size() - (relocation.offset - image.lowestPage)))) {
                    error = "relocation references an invalid symbol or image offset";
                    image = {};
                    return false;
                }
            }
        }
    }
    return true;
}

} // namespace injector
