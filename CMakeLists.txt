cmake_minimum_required(VERSION 3.6.0)
project(example VERSION 1.0.0 LANGUAGES C)

add_subdirectory(backend/quicly)

add_executable(echo src/echo.c)

target_link_libraries(echo PRIVATE quicly ev picotls)
target_compile_definitions(echo PRIVATE QPERF_VERSION="${PROJECT_VERSION}")
target_compile_options(echo PRIVATE
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=shift-count-overflow
)

