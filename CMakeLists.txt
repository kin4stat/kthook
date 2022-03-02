cmake_minimum_required(VERSION 3.15)
project(kthook)

option(KTHOOK_TEST "Compile tests" OFF)

add_subdirectory(ktsignal)
add_subdirectory(xbyak)
add_subdirectory(hde)

add_library(${PROJECT_NAME} INTERFACE)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(${PROJECT_NAME} INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                                                      $<INSTALL_INTERFACE:include/${PROJECT_NAME}> ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} INTERFACE ktsignal xbyak hde)

if(KTHOOK_TEST)
    add_subdirectory("tests")
endif()
