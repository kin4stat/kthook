cmake_minimum_required(VERSION 3.15)
project(kthook)

option(KTHOOK_TEST "Compile tests" OFF)

add_subdirectory(ktsignal)
add_subdirectory(xbyak)
add_subdirectory(hde)

add_library(${PROJECT_NAME} INTERFACE)

target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_17)

target_include_directories(${PROJECT_NAME} INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                                                      $<INSTALL_INTERFACE:include/${PROJECT_NAME}> ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} INTERFACE ktsignal xbyak hde)

target_compile_definitions(${PROJECT_NAME} INTERFACE NOMINMAX)

if(KTHOOK_TEST)
    if (MSVC)
        STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
        add_compile_options("/GS-")
    endif()
    add_subdirectory("tests")
endif()
