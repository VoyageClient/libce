cmake_minimum_required(VERSION 3.10)

project(ce VERSION 0.1.0 LANGUAGES CXX C)

option(CE_TESTS "Build tests" ON)
option(BUILD_SHARED_LIBS "Build as a shared library" ON)

add_definitions(-DLIBCE_VERSION_MAJOR=${PROJECT_VERSION_MAJOR})
add_definitions(-DLIBCE_VERSION_MINOR=${PROJECT_VERSION_MINOR})
add_definitions(-DLIBCE_VERSION_PATCH=${PROJECT_VERSION_PATCH})

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

add_library(ce
    src/account.cpp
    src/base64.c
    src/cipher.c
    src/crypto.cpp
    src/memory.c
    src/message.cpp
    src/pickle.cpp
    src/ratchet.cpp
    src/session.cpp
    src/utility.cpp
    src/pk.cpp
    src/sas.c

    src/ed25519.c
    src/error.c
    src/inbound_group_session.c
    src/megolm.c
    src/olm.cpp
    src/outbound_group_session.c
    src/pickle_encoding.c

    lib/crypto-algorithms/aes.c
    lib/crypto-algorithms/sha256.c
    lib/curve25519-donna/curve25519-donna.c)
add_library(LibCE::LibCE ALIAS ce)

# restrict the exported symbols
include(GenerateExportHeader)
generate_export_header(ce
  EXPORT_FILE_NAME ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/olm_export.h)

target_include_directories(ce
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set_target_properties(ce PROPERTIES
   SOVERSION ${PROJECT_VERSION_MAJOR}
   VERSION ${PROJECT_VERSION})

set_target_properties(ce PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

include(GNUInstallDirs)

# Make a pkg-config file
configure_file(libce.pc.in libce.pc @ONLY NEWLINE_STYLE UNIX)

#
# Installation
#
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/ce)
install(TARGETS ce
    EXPORT ce-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# The exported target will be named LibCE.
set_target_properties(ce PROPERTIES EXPORT_NAME LibCE)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/olm.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/olm_export.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/outbound_group_session.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/inbound_group_session.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/pk.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/sas.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libce/error.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libce)

if (UNIX AND NOT APPLE)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )
endif ()

# Export the targets to a script.
install(EXPORT ce-targets
  FILE CETargets.cmake
  NAMESPACE LibCE::
  DESTINATION ${INSTALL_CONFIGDIR})

# Create a ConfigVersion.cmake file.
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/CEConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

configure_package_config_file(
    ${CMAKE_CURRENT_LIST_DIR}/cmake/CEConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CEConfig.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR})

#Install the config & configversion.
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/CEConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/CEConfigVersion.cmake
    DESTINATION ${INSTALL_CONFIGDIR})

# Register package in user's package registry
export(EXPORT ce-targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/CETargets.cmake
    NAMESPACE LibCE::)
export(PACKAGE LibCE)

if (CE_TESTS)
   add_subdirectory(tests)
endif()
