# We don't need to export any symbol implicitly, and also disable C++ exceptions, and enable unwind tables.
include("${CMAKE_CURRENT_LIST_DIR}/reproducible-paths.cmake")
set(CMAKE_C_FLAGS_INIT "${CMAKE_C_FLAGS_INIT} -fvisibility=hidden -fno-exceptions -funwind-tables -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_CXX_FLAGS_INIT} -fvisibility=hidden -fno-exceptions -funwind-tables -fno-omit-frame-pointer")
