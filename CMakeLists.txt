cmake_minimum_required(VERSION 3.10)

project(rnd VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP QUIET libpcap)

if(NOT PCAP_FOUND)
    message(STATUS "libpcap не найден! Установка...")
    execute_process(COMMAND sudo apt update)
    execute_process(COMMAND sudo apt install -y libpcap-dev)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
endif()

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
add_definitions(${PCAP_CFLAGS_OTHER})

add_compile_options(-Wall -Wextra -Wpedantic -finput-charset=UTF-8 -fexec-charset=UTF-8)
include_directories(src/sniffer)

set(SNIFFER_SOURCES src/sniffer/sniffer.cpp)
    
add_library(SNIFFER ${SNIFFER_SOURCES})
target_include_directories(SNIFFER PUBLIC SNIFFER)

include_directories(src/handlers)
set(HANDLERS_SOURCES src/handlers/handlers.cpp)

add_library(HANDLERS ${HANDLERS_SOURCES})

target_include_directories(HANDLERS PUBLIC HANDLERS)

target_link_libraries(HANDLERS PUBLIC SNIFFER)

add_executable(main src/main.cpp)

target_link_libraries(main PUBLIC HANDLERS SNIFFER pcap)
