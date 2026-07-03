cmake_minimum_required(VERSION 3.20)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
project(Wirewolf LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_ARCHITECTURES "89")
set(CMAKE_CUDA_FLAGS "-allow-unsupported-compiler -diag-suppress 177,221,550")

option(WIREWOLF_USE_OPENVINO "Build with OpenVINO support" OFF)
option(WIREWOLF_USE_WINDIVERT "Build with WinDivert inline IPS support" OFF)
option(WIREWOLF_BUILD_TESTS "Build unit tests" OFF)
option(WIREWOLF_BUILD_GUI "Build Dear ImGui GUI frontend" OFF)

if(MSVC)
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/EHsc>" "$<$<COMPILE_LANGUAGE:CXX>:/Zc:char8_t->")
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/GS>" "$<$<COMPILE_LANGUAGE:CXX>:/sdl>")
    add_link_options(/DYNAMICBASE /NXCOMPAT /CETCOMPAT)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -pthread")
    add_compile_options(-fstack-protector-strong -D_FORTIFY_SOURCE=2)
    add_link_options(-Wl,-z,relro,-z,now)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

include(FetchContent)

# --- Npcap ---
FetchContent_Declare(
    npcap
    URL "https://npcap.com/dist/npcap-sdk-1.13.zip"
)
FetchContent_MakeAvailable(npcap)

add_library(pcap::pcap UNKNOWN IMPORTED)
set_target_properties(pcap::pcap PROPERTIES
    IMPORTED_LOCATION "${npcap_SOURCE_DIR}/Lib/x64/wpcap.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${npcap_SOURCE_DIR}/Include"
)

# --- WinDivert (optional, inline IPS) ---
if(WIREWOLF_USE_WINDIVERT)
    FetchContent_Declare(
        windivert
        URL "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
    )
    FetchContent_MakeAvailable(windivert)
    # The release zip extracts to a WinDivert-2.2.2-A/ subfolder.
    file(GLOB _WD_ROOT "${windivert_SOURCE_DIR}" "${windivert_SOURCE_DIR}/WinDivert-*")
    list(GET _WD_ROOT -1 WINDIVERT_DIR)
    message(STATUS "WinDivert SDK: ${WINDIVERT_DIR}")

    add_library(windivert::windivert SHARED IMPORTED)
    set_target_properties(windivert::windivert PROPERTIES
        IMPORTED_IMPLIB "${WINDIVERT_DIR}/x64/WinDivert.lib"
        IMPORTED_LOCATION "${WINDIVERT_DIR}/x64/WinDivert.dll"
        INTERFACE_INCLUDE_DIRECTORIES "${WINDIVERT_DIR}/include"
    )
    # Path to the runtime files that must be deployed beside the executable
    # (WinDivert.dll and the WinDivert64.sys kernel driver).
    set(WINDIVERT_RUNTIME_DIR "${WINDIVERT_DIR}/x64" CACHE PATH "" FORCE)
endif()

# --- OpenVINO (optional) ---
if(WIREWOLF_USE_OPENVINO)
    # Try pip-installed OpenVINO first (has NPU plugin), fallback to local source build
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_FOUND)
        execute_process(
            COMMAND ${Python3_EXECUTABLE} -c "import openvino; import os; print(os.path.join(os.path.dirname(openvino.__file__), 'cmake'))"
            OUTPUT_VARIABLE _OV_PIP_CMAKE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE _OV_PIP_RESULT
            ERROR_QUIET
        )
        if(_OV_PIP_RESULT EQUAL 0 AND EXISTS "${_OV_PIP_CMAKE_DIR}/OpenVINOConfig.cmake")
            set(OpenVINO_DIR "${_OV_PIP_CMAKE_DIR}" CACHE PATH "" FORCE)
            message(STATUS "Found pip-installed OpenVINO: ${_OV_PIP_CMAKE_DIR}")
        endif()
    endif()
    # Fallback: local source build
    if(NOT OpenVINO_DIR OR NOT EXISTS "${OpenVINO_DIR}/OpenVINOConfig.cmake")
        set(OpenVINO_DIR "${CMAKE_SOURCE_DIR}/openvino/build" CACHE PATH "" FORCE)
        message(STATUS "Using local OpenVINO build: ${OpenVINO_DIR}")
    endif()
    find_package(OpenVINO REQUIRED)
endif()

# --- CUDA ---
find_package(CUDAToolkit REQUIRED)

# --- llama.cpp ---
FetchContent_Declare(
    llama
    GIT_REPOSITORY https://github.com/ggerganov/llama.cpp.git
    GIT_TAG        177c75852a6a6fd6810ce23f50c77e4a60ea6828
)
set(GGML_CUDA ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(llama)

# --- Core library ---
add_library(wirewolf_core STATIC
    src/tcp_reassembly.cpp
    src/npu_filter.cpp
    src/llm_inference.cpp
    src/pipeline_controller.cpp
    src/alert_json.cpp
)

target_include_directories(wirewolf_core PUBLIC include)

target_link_libraries(wirewolf_core PUBLIC
    pcap::pcap
    llama
    CUDA::cudart
    CUDA::cublas
)

if(WIREWOLF_USE_OPENVINO)
    target_compile_definitions(wirewolf_core PUBLIC WIREWOLF_USE_OPENVINO)
    target_link_libraries(wirewolf_core PUBLIC openvino::runtime)
endif()

if(WIREWOLF_USE_WINDIVERT)
    target_compile_definitions(wirewolf_core PUBLIC WIREWOLF_USE_WINDIVERT)
    target_link_libraries(wirewolf_core PUBLIC windivert::windivert)
endif()

if(MSVC)
    target_link_libraries(wirewolf_core PUBLIC ws2_32)
endif()

# --- CLI executable ---
add_executable(wirewolf cli/main.cpp)
target_link_libraries(wirewolf PRIVATE wirewolf_core)

# --- Benchmark harness (detection efficacy measurement) ---
add_executable(wirewolf_bench bench/benchmark.cpp)
target_link_libraries(wirewolf_bench PRIVATE wirewolf_core)

# --- Fast behavioral probe (capture+reassembly only, no LLM) ---
add_executable(wirewolf_probe bench/probe.cpp)
target_link_libraries(wirewolf_probe PRIVATE wirewolf_core)

# --- Quick pcap IP breakdown (internal vs external) ---
add_executable(wirewolf_ipscan tool/ipscan.cpp)
target_link_libraries(wirewolf_ipscan PRIVATE wirewolf_core)

# --- Behavioral C2 model (clean-room): ONE shared encoder + Markov model.
# Deliberately std-only (no llama/pcap) so the offline trainer builds fast and
# the live engine can link the SAME code later with no encoding drift. ---
add_library(wirewolf_behavioral STATIC src/behavioral_model.cpp)
target_include_directories(wirewolf_behavioral PUBLIC include)
# The live engine links the SAME behavioral lib (one encoder, no drift).
target_link_libraries(wirewolf_core PUBLIC wirewolf_behavioral)

# Offline trainer: CTU-13 .binetflow -> Markov models + holdout evaluation.
add_executable(train_behavioral tools/train_behavioral/train.cpp)
target_link_libraries(train_behavioral PRIVATE wirewolf_behavioral)

# Export per-4-tuple state strings from a pcap using the ENGINE's own encoder
# (train-on-pcap pipeline: train features match runtime features exactly).
add_executable(export_states tools/export_states/export_states.cpp)
target_link_libraries(export_states PRIVATE wirewolf_core)

# --- Shared library for FFI (Flutter, Python, etc.) ---
option(WIREWOLF_BUILD_FFI "Build shared library with C API for FFI" OFF)
if(WIREWOLF_BUILD_FFI)
    add_library(wirewolf_ffi SHARED src/wirewolf_capi.cpp)
    target_include_directories(wirewolf_ffi PUBLIC include)
    target_link_libraries(wirewolf_ffi PRIVATE wirewolf_core)
    target_compile_definitions(wirewolf_ffi PRIVATE WIREWOLF_DLL_EXPORT)
    set_target_properties(wirewolf_ffi PROPERTIES
        OUTPUT_NAME "wirewolf"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/ffi"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/ffi"
    )
endif()

# --- GUI executable (optional) ---
if(WIREWOLF_BUILD_GUI)
    add_subdirectory(gui)
endif()

# --- Tests ---
if(WIREWOLF_BUILD_TESTS)
    # Build Catch2 as static library to avoid DLL path issues
    set(_saved_BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS})
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)

    set(BUILD_SHARED_LIBS ${_saved_BUILD_SHARED_LIBS} CACHE BOOL "" FORCE)

    add_executable(wirewolf_tests
        tests/test_thread_safe_queue.cpp
        tests/test_packet_types.cpp
        tests/test_npu_filter.cpp
        tests/test_config.cpp
    )
    target_include_directories(wirewolf_tests PRIVATE include)
    target_link_libraries(wirewolf_tests PRIVATE Catch2::Catch2WithMain)

    include(CTest)
    include(Catch)
    catch_discover_tests(wirewolf_tests)
endif()
