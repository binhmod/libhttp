cmake_minimum_required(VERSION 3.18)
project(libhttp)

find_library(log-lib log)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/mbedtls)

# ================= Target =================
add_executable(http http.cpp)

target_compile_options(http PRIVATE
    -Oz -flto
    -ffunction-sections -fdata-sections
    -fomit-frame-pointer
    -fvisibility=hidden -fvisibility-inlines-hidden
    -fno-rtti -fno-exceptions
    -fno-threadsafe-statics
    -fno-ident
    -fno-unwind-tables -fno-asynchronous-unwind-tables
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security
)

target_link_options(http PRIVATE
    -flto
    -Wl,--exclude-libs,ALL
    -Wl,--gc-sections -Wl,--strip-all
    -Wl,--icf=all
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    -Wl,--hash-style=sysv -Wl,--build-id=none
    -Wl,--pack-dyn-relocs=android
)

# ================= DEFINITIONS =================
set(COMMON_DEFS
    NDEBUG
    PRIVATE_IMPLEMENTATION HIDDEN_VISIBILITY
    MBEDTLS_CONFIG_FILE="mbedtls_config.h"
)

target_compile_definitions(http PRIVATE ${COMMON_DEFS})

target_include_directories(http PRIVATE
    third_party/mbedtls/include
)

target_link_libraries(http
    z
    mbedtls
    mbedx509
    mbedcrypto
    ${log-lib}
)

add_custom_command(TARGET http POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-all -R .comment -R .note -R .gnu.hash $<TARGET_FILE:http>
    COMMENT "strip http"
)