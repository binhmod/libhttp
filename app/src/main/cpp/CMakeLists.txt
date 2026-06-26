cmake_minimum_required(VERSION 3.18)
project(libhttp)

find_library(log-lib log)
find_package(boringssl REQUIRED CONFIG)

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
    -Wl,--pack-dyn-relocs=android   # thêm dòng này
)

# ================= DEFINITIONS =================
set(COMMON_DEFS
    NDEBUG BORINGSSL_NO_ASM OPENSSL_NO_SSL OPENSSL_NO_TLS
    OPENSSL_NO_OCSP OPENSSL_NO_ENGINE OPENSSL_NO_SRP OPENSSL_NO_COMP
    PRIVATE_IMPLEMENTATION HIDDEN_VISIBILITY
)

target_compile_definitions(http PRIVATE ${COMMON_DEFS})

target_link_libraries(http
    z
    boringssl::ssl_static
    boringssl::crypto_static
    ${log-lib}
)

add_custom_command(TARGET http POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-all -R .comment -R .note -R .gnu.hash $<TARGET_FILE:http>
    COMMENT "strip http"
)