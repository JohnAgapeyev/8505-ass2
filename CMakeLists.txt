cmake_minimum_required(VERSION 3.9.4)
project(8505-ass2)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "")
set(CMAKE_C_FLAGS_MINSIZEREL "")

set(BASE_COMPILE_OPTIONS -Wall -Wextra -pedantic -pipe -march=native)
set(DEBUG_OPTIONS ${BASE_COMPILE_OPTIONS} -g -O0)
set(RELEASE_OPTIONS ${BASE_COMPILE_OPTIONS} -s -O3)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL 1.1.0 REQUIRED)

set(MAIN_SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
)

set(ASS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/image.c
)

set(SOURCE_LIBRARY sig_lib)

add_library(${SOURCE_LIBRARY} ${ASS_SOURCES})

target_compile_options(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")

target_link_libraries(${SOURCE_LIBRARY} PUBLIC OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(${SOURCE_LIBRARY} PUBLIC
    src
)

add_executable(${PROJECT_NAME} ${MAIN_SOURCE})
target_link_libraries(${PROJECT_NAME} PRIVATE ${SOURCE_LIBRARY})

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

if(ipo_supported)
    message(STATUS "IPO / LTO enabled")
    set_target_properties(${SOURCE_LIBRARY} ${PROJECT_NAME} PROPERTIES 
        INTERPROCEDURAL_OPTIMIZATION TRUE 
        POSITION_INDEPENDENT_CODE TRUE
    )
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

