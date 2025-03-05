cmake_minimum_required(VERSION 3.6.0)
project(example VERSION 1.0.0 LANGUAGES C)

add_subdirectory(backend/quicly)

INCLUDE_DIRECTORIES(
    ${OPENSSL_INCLUDE_DIR}
    backend/quicly/deps/klib
    backend/quicly/deps/picotls/include
    backend/quicly/deps/picotest
    backend/quicly/include
    ${CMAKE_CURRENT_BINARY_DIR})

SET(PICOTLS_OPENSSL_FILES
    backend/quicly/deps/picotls/lib/hpke.c
    backend/quicly/deps/picotls/lib/openssl.c
    backend/quicly/deps/picotls/lib/pembase64.c
    backend/quicly/deps/picotls/lib/picotls.c)

SET(QUICLY_LIBRARY_FILES
    backend/quicly/lib/frame.c
    backend/quicly/lib/cc-reno.c
    backend/quicly/lib/cc-cubic.c
    backend/quicly/lib/cc-pico.c
    backend/quicly/lib/defaults.c
    backend/quicly/lib/local_cid.c
    backend/quicly/lib/loss.c
    backend/quicly/lib/quicly.c
    backend/quicly/lib/ranges.c
    backend/quicly/lib/rate.c
    backend/quicly/lib/recvstate.c
    backend/quicly/lib/remote_cid.c
    backend/quicly/lib/retire_cid.c
    backend/quicly/lib/sendstate.c
    backend/quicly/lib/sentmap.c
    backend/quicly/lib/streambuf.c
    ${CMAKE_CURRENT_BINARY_DIR}/quicly-tracer.h)


add_executable(echo src/echo.c)

target_link_libraries(echo PRIVATE quicly ev picotls)
target_compile_definitions(echo PRIVATE QPERF_VERSION="${PROJECT_VERSION}")
target_compile_options(echo PRIVATE
    -Werror=implicit-function-declaration
    -Werror=shift-count-overflow
)

