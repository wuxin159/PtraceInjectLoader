#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace injector {

struct LoadSegment {
    std::uint64_t virtualAddress{};
    std::uint64_t fileOffset{};
    std::uint64_t fileSize{};
    std::uint64_t memorySize{};
    std::uint32_t flags{};
    std::uint64_t alignment{};
};

struct DynamicSymbol {
    std::string name;
    std::uint64_t value{};
    std::uint64_t size{};
    std::uint8_t info{};
    std::uint8_t other{};
    std::uint16_t sectionIndex{};
    std::uint16_t versionIndex{};
    bool versionHidden{};
    std::string versionName;
    std::string versionLibrary;
};

struct DynamicRelocation {
    std::uint64_t offset{};
    std::uint64_t symbolIndex{};
    std::uint32_t type{};
    std::int64_t addend{};
};

struct ElfImage {
    std::uint64_t lowestPage{};
    std::uint64_t imageSize{};
    std::vector<LoadSegment> segments;
    std::vector<std::string> neededLibraries;
    std::string soname;
    std::vector<DynamicSymbol> symbols;
    std::vector<DynamicRelocation> relocations;
    std::vector<std::uint64_t> relativeRelocations;
    std::uint64_t initArrayAddress{};
    std::uint64_t initFunction{};
    std::uint64_t relocationCount{};
    std::uint64_t relativeRelocationCount{};
    std::uint64_t initArrayCount{};
    bool hasTls{};
    std::vector<std::uint8_t> memory;
};

bool parseElfImage(const std::vector<std::uint8_t>& file,
                   std::uint64_t maxImageSize,
                   ElfImage& image,
                   std::string& error);

} // namespace injector
