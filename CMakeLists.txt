cmake_minimum_required(VERSION 3.21)

project(cpueaxh LANGUAGES CXX)

option(CPUEAXH_BUILD_EXAMPLE "Build the user-mode example program" ON)
option(CPUEAXH_BUILD_TESTS "Build the user-mode test executable" ON)
option(CPUEAXH_BUILD_SHARED "Build a Windows DLL for FFI / Python glue" ON)
option(CPUEAXH_BUILD_NATIVE_BRIDGES "Build a small DLL exporting native escape bridge stubs for Python glue" ON)

if(NOT WIN32)
    message(FATAL_ERROR "The current CMake build supports Windows user-mode builds only.")
endif()

if(NOT MSVC)
    message(FATAL_ERROR "The current CMake build requires MSVC because the project uses MASM and MSVC intrinsics.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
endif()

function(cpueaxh_apply_common_msvc_settings target_name)
    target_compile_features(${target_name} PUBLIC cxx_std_20)
    set_property(TARGET ${target_name} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_options(${target_name} PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/W3>
        $<$<COMPILE_LANGUAGE:CXX>:/sdl>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
    )
endfunction()

add_library(cpueaxh_obj OBJECT
    cpueaxh/cpueaxh.cpp
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_sources(cpueaxh_obj PRIVATE cpueaxh/host_bridge.asm)
endif()

target_include_directories(cpueaxh_obj
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpueaxh>
        $<INSTALL_INTERFACE:include>
)

cpueaxh_apply_common_msvc_settings(cpueaxh_obj)

add_library(cpueaxh STATIC
    $<TARGET_OBJECTS:cpueaxh_obj>
)

add_library(cpueaxh::cpueaxh ALIAS cpueaxh)

target_include_directories(cpueaxh
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpueaxh>
        $<INSTALL_INTERFACE:include>
)

cpueaxh_apply_common_msvc_settings(cpueaxh)

if(CPUEAXH_BUILD_SHARED)
    add_library(cpueaxh_shared SHARED
        $<TARGET_OBJECTS:cpueaxh_obj>
    )

    add_library(cpueaxh::cpueaxh_shared ALIAS cpueaxh_shared)

    target_include_directories(cpueaxh_shared
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cpueaxh>
            $<INSTALL_INTERFACE:include>
    )

    set_target_properties(cpueaxh_shared PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        OUTPUT_NAME cpueaxh_shared
    )

    cpueaxh_apply_common_msvc_settings(cpueaxh_shared)
endif()

if(CPUEAXH_BUILD_EXAMPLE)
    add_executable(cpueaxh_example
        example/main.cpp
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_sources(cpueaxh_example PRIVATE example/demo/escape/escape.asm)
    endif()

    target_link_libraries(cpueaxh_example PRIVATE cpueaxh)
    target_include_directories(cpueaxh_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/cpueaxh)
    cpueaxh_apply_common_msvc_settings(cpueaxh_example)
endif()

if(CPUEAXH_BUILD_NATIVE_BRIDGES AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_library(cpueaxh_native_bridges SHARED
        python/native_bridges/bridge_helpers.cpp
        python/native_bridges/dllmain.cpp
        example/demo/escape/escape.asm
    )

    set_target_properties(cpueaxh_native_bridges PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        OUTPUT_NAME cpueaxh_native_bridges
    )

    cpueaxh_apply_common_msvc_settings(cpueaxh_native_bridges)
endif()

if(CPUEAXH_BUILD_TESTS)
    add_executable(cpueaxh_test
        test/main.cpp
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_sources(cpueaxh_test PRIVATE test/demo/native_runner.asm)
    endif()

    target_link_libraries(cpueaxh_test PRIVATE cpueaxh)
    target_include_directories(cpueaxh_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/cpueaxh)
    cpueaxh_apply_common_msvc_settings(cpueaxh_test)
endif()

install(TARGETS cpueaxh
    EXPORT cpueaxhTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

if(CPUEAXH_BUILD_SHARED)
    install(TARGETS cpueaxh_shared
        EXPORT cpueaxhTargets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
    )
endif()

if(CPUEAXH_BUILD_NATIVE_BRIDGES AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(TARGETS cpueaxh_native_bridges
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
    )
endif()

install(FILES cpueaxh/cpueaxh.hpp DESTINATION include)

install(EXPORT cpueaxhTargets
    FILE cpueaxhTargets.cmake
    NAMESPACE cpueaxh::
    DESTINATION lib/cmake/cpueaxh
)
