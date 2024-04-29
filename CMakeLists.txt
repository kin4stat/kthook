cmake_minimum_required(VERSION 3.15)
project(kthook)

option(KTHOOK_TEST "Compile tests" OFF)

add_subdirectory(ktsignal)
add_subdirectory(hde)

include(FetchContent)

FetchContent_Declare(
	xbyak
	GIT_REPOSITORY https://github.com/herumi/xbyak.git
	GIT_TAG v6.69.1
)

FetchContent_MakeAvailable(xbyak)


add_library(${PROJECT_NAME} INTERFACE)

target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_20)

target_include_directories(${PROJECT_NAME} INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                                                      $<INSTALL_INTERFACE:include/${PROJECT_NAME}> ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} INTERFACE ktsignal xbyak hde)

target_compile_definitions(${PROJECT_NAME} INTERFACE NOMINMAX)

add_executable(test1 main.cpp)
target_link_libraries(test1 PRIVATE ${PROJECT_NAME})

# if(KTHOOK_TEST)
#     if (MSVC)
#         STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
#         add_compile_options("/GS-")
#     endif()
#     add_subdirectory("tests")
# endif()
