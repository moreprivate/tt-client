cmake_minimum_required(VERSION 3.24)
if(NOT CMAKE_INSTALL_PREFIX MATCHES "conan2")
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "cmake/reproducible_conan.cmake")
endif()
project(vpn_libs C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

option(VPNLIBS_ENABLE_LIVE_TESTS "Register live tests in CTest" OFF)
option(VPNLIBS_CAPI_LINUX_EXPORTS "Resolve WIN_EXPORT to default visibility in Linux C API package builds" OFF)

if (DISABLE_HTTP3)
    add_compile_definitions(DISABLE_HTTP3)
endif ()

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)

    add_compile_definitions(_WIN32_WINNT=0x0601)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)

    add_compile_options(/Oy-) # -fno-omit-frame-pointer
else ()
    add_compile_options(-fno-omit-frame-pointer)
    # Keep source locations embedded by __FILE__ and debug records stable.
    add_compile_options(
        "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=/tt-client"
        "-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=/tt-client"
    )
endif ()

if (IPV6_UNAVAILABLE)
    add_compile_definitions(IPV6_UNAVAILABLE)
endif()

if (SANITIZE)
    add_compile_options("-fsanitize=address")
    link_libraries("-fsanitize=address")
endif(SANITIZE)

if (CMAKE_SYSTEM_NAME STREQUAL Linux AND VPNLIBS_CAPI_LINUX_EXPORTS)
    add_compile_definitions(VPNLIBS_CAPI_LINUX_EXPORTS=1)
endif()

add_subdirectory(core)
add_subdirectory(trusttunnel)

enable_testing()
