cmake_minimum_required(VERSION 3.0)
project(kthook)

if (NOT DEFINED KTHOOK_TEST)
  set(KTHOOK_TEST FALSE)
endif()

add_subdirectory(ktsignal)

file(GLOB ${PROJECT_NAME}_LIST
	${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/*.c
	${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/*.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/*.cxx
	${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/x86/*.c
	${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/x86/*.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/x86/*.cxx
	${CMAKE_CURRENT_SOURCE_DIR}/hde/*.c
	${CMAKE_CURRENT_SOURCE_DIR}/hde/*.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/hde/*.cxx
	${CMAKE_CURRENT_SOURCE_DIR}/xbyak/*.c
	${CMAKE_CURRENT_SOURCE_DIR}/xbyak/*.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/xbyak/*.cxx
)
file(GLOB ${PROJECT_NAME}_LIST_H
        ${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/*.hxx
        ${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/x86/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/x86/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/kthook/x86/*.hxx
        ${CMAKE_CURRENT_SOURCE_DIR}/hde/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/hde/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/hde/*.hxx
        ${CMAKE_CURRENT_SOURCE_DIR}/xbyak/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/xbyak/*.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/xbyak/*.hxx
)

add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_LIST} ${${PROJECT_NAME}_LIST_H})

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} ktsignal)

if(KTHOOK_TEST)
    if (${AARCH} MATCHES "(x86)|(X86)")
        set (X86 TRUE)
    else ()
        set (X86 FALSE)
    endif ()
    set(CMAKE_CXX_STANDARD 17)
    set(CXX_STANDARD_REQUIRED YES)
    set(CXX_EXTENSIONS NO)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/e2239ee6043f73722e7aa812a459f54a28552929.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_disable_pthreads ON)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    include(GoogleTest)

    enable_testing()
    file(GLOB TEST_SRC_FILES ${PROJECT_SOURCE_DIR}/tests/*.cpp)
    
    if (X86)
        file(COPY_FILE ${PROJECT_SOURCE_DIR}/tests/test_common.hpp "${CMAKE_BINARY_DIR}/test_common.hpp")
    endif()
    # from list of files we'll create tests test_name.cpp -> test_name
    foreach(_test_file ${TEST_SRC_FILES})
        get_filename_component(_test_name ${_test_file} NAME_WE)
        get_filename_component(_test_full_filename ${_test_file} NAME)
        if(X86)
            if (UNIX)
                foreach (conv CSTDCALL CTHISCALL CCDECL)
                    string(CONCAT conv_name ${conv} "-TEST")
                    file(COPY_FILE ${_test_file} "${CMAKE_BINARY_DIR}/${_test_name}-${conv}.cpp")
                    add_executable(${_test_name}-${conv} "${CMAKE_BINARY_DIR}/${_test_name}-${conv}.cpp")
                    target_compile_definitions(${_test_name}-${conv} PRIVATE TEST_CCONV=${conv} CONV_NAME=${conv_name})
                    target_link_libraries(${_test_name}-${conv} gtest gtest_main ${PROJECT_NAME})
                    add_test(${_test_name}-${conv} ${_test_name}-${conv})
                    set_tests_properties(${_test_name}-${conv} PROPERTIES TIMEOUT 5)
                endforeach()
            else()
                foreach (conv CFASTCALL CSTDCALL CCDECL CTHISCALL)
                    string(CONCAT conv_name ${conv} "-TEST")
                    file(COPY_FILE ${_test_file} "${CMAKE_BINARY_DIR}/${_test_name}-${conv}.cpp")
                    add_executable(${_test_name}-${conv} "${CMAKE_BINARY_DIR}/${_test_name}-${conv}.cpp")
                    target_compile_definitions(${_test_name}-${conv} PRIVATE TEST_CCONV=${conv} CONV_NAME=${conv_name})
                    target_link_libraries(${_test_name}-${conv} gtest gtest_main ${PROJECT_NAME})
                    add_test(${_test_name}-${conv} ${_test_name}-${conv})
                    set_tests_properties(${_test_name}-${conv} PROPERTIES TIMEOUT 5)
                endforeach()
            endif()
        else()
            add_executable(${_test_name} ${_test_file})
            target_link_libraries(${_test_name} gtest gtest_main ${PROJECT_NAME})
            add_test(${_test_name} ${_test_name})
            set_tests_properties(${_test_name} PROPERTIES TIMEOUT 5)
        endif()
    endforeach()
endif()
