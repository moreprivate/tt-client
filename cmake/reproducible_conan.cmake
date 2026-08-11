# Load the upstream Conan dependency provider, then override only the profile
# inputs which otherwise vary with the machine running the build.
include(${CMAKE_CURRENT_LIST_DIR}/conan_bootstrap.cmake)

get_filename_component(_TT_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(_TT_PROFILE_DIR "${_TT_ROOT}/scripts/conan-profiles")

if(NOT EXISTS "${_TT_PROFILE_DIR}/build-linux")
    message(FATAL_ERROR "Missing deterministic Conan build profile")
endif()
if(NOT EXISTS "${_TT_PROFILE_DIR}/reproducible-paths")
    message(FATAL_ERROR "Missing deterministic Conan path profile")
endif()

# Conan package IDs include build-context settings.  Never use its detected
# default profile here: the runner/compiler used to detect it is not part of
# the source revision and changes the selected binaries.
set(CONAN_BUILD_PROFILE "${_TT_PROFILE_DIR}/build-linux" CACHE STRING "Conan build profile" FORCE)

# The generated upstream profiles include Conan's detected `default` profile.
# That profile is runner-dependent and is absent when CI deliberately skips
# profile detection.  Make a local copy without that include while retaining
# the generated profile's target compiler/ABI/toolchain settings.
if(DEFINED _SELECTED_PROFILE AND EXISTS "${_SELECTED_PROFILE}")
    get_filename_component(_TT_UPSTREAM_PROFILE_DIR "${_SELECTED_PROFILE}" DIRECTORY)
    file(READ "${_SELECTED_PROFILE}" _TT_HOST_PROFILE_TEXT)
    string(REPLACE "include(default)" "" _TT_HOST_PROFILE_TEXT "${_TT_HOST_PROFILE_TEXT}")
    # Conan resolves named includes only through its global profile folders.
    # The deterministic path profile is supplied explicitly below, so remove
    # any generated named include instead of relying on runner-local state.
    string(REPLACE "include(reproducible-paths)" "" _TT_HOST_PROFILE_TEXT "${_TT_HOST_PROFILE_TEXT}")
    # The upstream jinja profiles inherit `os` from Conan's detected default
    # profile. That inheritance is intentionally removed for reproducibility,
    # so keep the required platform setting in this standalone profile.
    if(NOT _TT_HOST_PROFILE_TEXT MATCHES "(^|\\n)os=")
        string(REPLACE "[settings]\n" "[settings]\nos=${CMAKE_SYSTEM_NAME}\n" _TT_HOST_PROFILE_TEXT "${_TT_HOST_PROFILE_TEXT}")
    endif()
    string(REPLACE "{{profile_dir}}" "${_TT_UPSTREAM_PROFILE_DIR}" _TT_HOST_PROFILE_TEXT "${_TT_HOST_PROFILE_TEXT}")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^mips(el)?$")
        string(APPEND _TT_HOST_PROFILE_TEXT
            "\n[options]\nopenssl/*:no_fips=True\n")
    endif()
    set(_TT_HOST_PROFILE "${CMAKE_BINARY_DIR}/tt-client-host-profile")
    file(WRITE "${_TT_HOST_PROFILE}" "${_TT_HOST_PROFILE_TEXT}")
else()
    message(FATAL_ERROR "Unable to locate the generated Conan target profile")
endif()

set(CONAN_HOST_PROFILE "${_TT_HOST_PROFILE};auto-cmake;${_TT_PROFILE_DIR}/reproducible-paths" CACHE STRING "Conan host profile" FORCE)

unset(_TT_PROFILE_DIR)
unset(_TT_ROOT)
unset(_TT_HOST_PROFILE)
unset(_TT_HOST_PROFILE_TEXT)
unset(_TT_UPSTREAM_PROFILE_DIR)
