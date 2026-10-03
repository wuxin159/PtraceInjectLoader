#pragma once

#include "elf_image.hpp"
#include "target_process.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace injector {

struct ResolvedTargetSymbol {
    std::uint64_t address{};
    std::uint64_t loadBias{};
    std::string libraryPath;
};

bool resolveTargetSymbol(const std::vector<MemoryMap>& maps,
                         const std::string& name,
                         ResolvedTargetSymbol& symbol,
                         std::string& error);

bool loadWithTargetMemory(TargetProcess& target,
                          int tid,
                          const ElfImage& payloadElf,
                          const std::string& entryName,
                          const std::array<std::uint64_t, 8>& entryArgs,
                          std::uint64_t imageBase,
                          std::int64_t& entryResult,
                          std::string& error);

} // namespace injector
