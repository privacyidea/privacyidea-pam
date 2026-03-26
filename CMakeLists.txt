cmake_minimum_required(VERSION 3.10)
project(pam_privacyidea CXX)

# Determine install path based on architecture
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(PAM_LIBDIR "/lib64/security" CACHE PATH "PAM modules directory")
else()
    set(PAM_LIBDIR "/lib/security" CACHE PATH "PAM modules directory")
endif()

add_library(pam_privacyidea MODULE
    src/pam_privacyidea.cpp
    src/privacyidea.cpp
)

target_include_directories(pam_privacyidea PRIVATE include)

target_compile_options(pam_privacyidea PRIVATE -Wall -Wno-undef)

target_link_libraries(pam_privacyidea PRIVATE curl crypto ssl pam)

# Remove the default "lib" prefix so the output is pam_privacyidea.so
set_target_properties(pam_privacyidea PROPERTIES PREFIX "")

install(TARGETS pam_privacyidea
    LIBRARY DESTINATION "${PAM_LIBDIR}"
)
