cmake_minimum_required(VERSION 3.24)

project(
    UniversalWatermarkDisabler
    VERSION 2.0.0
    DESCRIPTION "Fail-closed Windows Insider/evaluation watermark controller"
    LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "Universal Watermark Disabler builds only on Windows.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(universal_tui STATIC
    third_party/universal-tui/utui.c)
target_include_directories(universal_tui PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/universal-tui")
set_target_properties(universal_tui PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO)

add_executable(uwd
    src/main.c
    src/pe_scan.c
    src/windows_backend.c
    resources/uwd.rc)
target_include_directories(uwd PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/resources")
target_compile_definitions(uwd PRIVATE
    UNICODE
    _UNICODE
    WINVER=0x0A00
    _WIN32_WINNT=0x0A00)
target_link_libraries(uwd PRIVATE
    universal_tui
    advapi32
    bcrypt
    dbghelp
    ole32
    shell32
    user32
    uuid
    winhttp)

if(MSVC)
    target_compile_options(universal_tui PRIVATE /W3 /utf-8)
    target_compile_options(uwd PRIVATE /W4 /WX /sdl /guard:cf /utf-8)
    target_link_libraries(uwd PRIVATE delayimp)
    target_link_options(uwd PRIVATE
        /guard:cf
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        /DELAYLOAD:dbghelp.dll
        /DELAYLOAD:winhttp.dll
        "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/resources/uwd.manifest")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
        target_link_options(uwd PRIVATE /CETCOMPAT)
    endif()
else()
    target_compile_options(universal_tui PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(uwd PRIVATE -Wall -Wextra -Wpedantic)
    if(MINGW)
        target_link_options(uwd PRIVATE -municode)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(pe_scan_tests
        tests/pe_scan_tests.c
        src/pe_scan.c)
    target_include_directories(pe_scan_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")
    if(MSVC)
        target_compile_options(pe_scan_tests PRIVATE /W4 /WX /sdl /guard:cf /utf-8)
        target_link_options(pe_scan_tests PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT)
    else()
        target_compile_options(pe_scan_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME pe_scan_bounds COMMAND pe_scan_tests)

    add_executable(symbol_resolver_tests
        tests/symbol_resolver_tests.c
        src/pe_scan.c
        src/windows_backend.c)
    target_include_directories(symbol_resolver_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_definitions(symbol_resolver_tests PRIVATE
        UNICODE
        _UNICODE
        WINVER=0x0A00
        _WIN32_WINNT=0x0A00)
    target_link_libraries(symbol_resolver_tests PRIVATE
        advapi32
        bcrypt
        dbghelp
        ole32
        shell32
        user32
        uuid
        winhttp)
    if(MSVC)
        target_compile_options(symbol_resolver_tests PRIVATE
            /W4 /WX /sdl /guard:cf /utf-8)
        target_link_libraries(symbol_resolver_tests PRIVATE delayimp)
        target_link_options(symbol_resolver_tests PRIVATE
            /guard:cf
            /DYNAMICBASE
            /HIGHENTROPYVA
            /NXCOMPAT
            /DELAYLOAD:dbghelp.dll
            /DELAYLOAD:winhttp.dll)
        if(CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
            target_link_options(symbol_resolver_tests PRIVATE /CETCOMPAT)
        endif()
    elseif(MINGW)
        target_compile_options(symbol_resolver_tests PRIVATE
            -Wall -Wextra -Wpedantic)
        target_link_options(symbol_resolver_tests PRIVATE -municode)
    endif()
endif()

install(TARGETS uwd RUNTIME DESTINATION .)
install(
    FILES third_party/universal-tui/LICENSE
    DESTINATION .
    RENAME LICENSE.Universal-TUI.txt)
