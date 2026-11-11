cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer VERSION 1.0 LANGUAGES CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

set(PACKET_ANALYZER_CORE_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

function(configure_packet_analyzer_target target_name)
    target_include_directories(${target_name} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
    )
    target_link_libraries(${target_name} PRIVATE Threads::Threads)
endfunction()

# Full modular engine: load balancers, fast paths, connection tracking,
# rule management, and PCAP input/output.
add_executable(dpi_engine
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/connection_tracker.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/rule_manager.cpp
    ${PACKET_ANALYZER_CORE_SOURCES}
)
configure_packet_analyzer_target(dpi_engine)

# Standalone multithreaded implementation.
add_executable(dpi_mt
    src/dpi_mt.cpp
    ${PACKET_ANALYZER_CORE_SOURCES}
)
configure_packet_analyzer_target(dpi_mt)

# Easier single-threaded implementation for learning and small PCAPs.
add_executable(dpi_simple
    src/main_working.cpp
    ${PACKET_ANALYZER_CORE_SOURCES}
)
configure_packet_analyzer_target(dpi_simple)

# Basic packet-header viewer retained as a separate utility.
add_executable(packet_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)
target_include_directories(packet_analyzer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

if(BUILD_TESTING)
    add_executable(dpi_engine_tests
        tests/engine_tests.cpp
        src/dpi_engine.cpp
        src/connection_tracker.cpp
        src/fast_path.cpp
        src/load_balancer.cpp
        src/rule_manager.cpp
        ${PACKET_ANALYZER_CORE_SOURCES}
    )
    configure_packet_analyzer_target(dpi_engine_tests)
    add_test(NAME engine_regressions COMMAND dpi_engine_tests)
endif()
