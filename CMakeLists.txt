cmake_minimum_required(VERSION 3.22)

set(NDK_PATH "D:/NDK/Android_NDK_r21b_goron")
set(CMAKE_TOOLCHAIN_FILE "${NDK_PATH}/build/cmake/android.toolchain.cmake")
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 26)
set(ANDROID_PLATFORM android-26)
set(ANDROID_ABI arm64-v8a)

project(PtraceInjectLoader LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Os -ffunction-sections -fdata-sections -fPIE)
add_link_options(-Wl,--gc-sections -Wl,--strip-all -s -fPIE -pie)

add_executable(PtraceInjectLoader
        main.cpp
        elf_image.cpp
        linker_loader.cpp
        target_process.cpp
)

target_link_libraries(PtraceInjectLoader PRIVATE log)
