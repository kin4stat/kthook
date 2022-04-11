cmake_minimum_required(VERSION 3.15)
project(kthook)

option(KTHOOK_TEST "Compile tests" OFF)

add_subdirectory(hde)

add_library(${PROJECT_NAME} INTERFACE)

target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_17)

target_include_directories(${PROJECT_NAME} INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                                                      $<INSTALL_INTERFACE:include/${PROJECT_NAME}> ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} INTERFACE ktsignal xbyak hde)

if(KTHOOK_TEST)
    add_subdirectory("tests")
endif()
