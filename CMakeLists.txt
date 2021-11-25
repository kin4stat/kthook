cmake_minimum_required(VERSION 3.0)
project(kthook)

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

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} ktsignal)
