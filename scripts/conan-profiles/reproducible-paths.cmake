# The outer tt-manage build supplies constant Conan cache-root maps through
# CFLAGS/CXXFLAGS. Do not derive flags from the live package directory here:
# that directory contains a Conan package ID and would make the package graph
# self-referential and unstable between clean builds.
