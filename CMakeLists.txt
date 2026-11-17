cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)
project(CertificateInstaller VERSION 1.0.0 LANGUAGES CXX RC)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "Use MSVC with the Windows SDK on Windows.")
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_definitions(UNICODE _UNICODE WINVER=0x0601 _WIN32_WINNT=0x0601 NOMINMAX)
add_compile_options(/utf-8 /W4 /EHsc)

add_library(certificate_import STATIC certificate_import.cpp)
target_link_libraries(certificate_import PUBLIC crypt32 advapi32)

add_executable(CertificateInstaller WIN32 main.cpp app.rc)
target_link_libraries(CertificateInstaller PRIVATE certificate_import comctl32 comdlg32 shell32 user32 gdi32)
target_link_options(CertificateInstaller PRIVATE /SUBSYSTEM:WINDOWS,6.01 /MANIFEST:NO)

enable_testing()
add_executable(certificate_import_tests tests.cpp)
target_link_libraries(certificate_import_tests PRIVATE certificate_import)
target_link_options(certificate_import_tests PRIVATE /SUBSYSTEM:CONSOLE,6.01)
add_test(NAME memory_store_regression COMMAND certificate_import_tests)
