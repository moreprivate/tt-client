if (NOT EXISTS ${CMAKE_CURRENT_LIST_DIR}/conan_provider.cmake)
    message(FATAL_ERROR "Missing checked-in cmake/conan_provider.cmake")
endif ()
include(${CMAKE_CURRENT_LIST_DIR}/conan_provider.cmake)
