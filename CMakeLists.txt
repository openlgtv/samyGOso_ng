project(samygoso C ASM)
cmake_minimum_required(VERSION 3.0)
set(CMAKE_BUILD_TYPE Debug)

include (CheckSymbolExists)
include (CheckTypeSize)

check_symbol_exists("__arm__" "" TARGET_ARM)
check_symbol_exists("__thumb__" "" TARGET_THUMB)
check_symbol_exists("__i386__" "" TARGET_I386)
check_symbol_exists("__x86_64__" "" TARGET_AMD64)
check_type_size("void *" SIZEOF_POINTER)
if(SIZEOF_POINTER EQUAL 4)
	set(CPU_32)
elseif(SIZEOF_POINTER EQUAL 8)
	set(CPU_64)
endif()
configure_file(${CMAKE_SOURCE_DIR}/config.h.in ${CMAKE_BINARY_DIR}/config.h)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/out)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/out)

set(CMAKE_C_STANDARD 99)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=implicit-function-declaration")

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
)
set(SHARED_DIR "${CMAKE_SOURCE_DIR}/shared")

add_subdirectory(core)
add_subdirectory(shared)
add_subdirectory(modules)
