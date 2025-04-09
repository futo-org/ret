cmake_minimum_required(VERSION 3.10)
project(fudge)

set(CMAKE_C_FLAGS_RELEASE -O3)
set(CMAKE_CXX_FLAGS_RELEASE -O3)

option(BUILD_LIBS_ONLY "" ON)
option(BUILD_SHARED_LIBS "" OFF)
option(CAPSTONE_ARCHITECTURE_DEFAULT "" OFF)
option(CAPSTONE_ARM_SUPPORT "" ON)
option(CAPSTONE_AARCH64_SUPPORT "" ON)
option(CAPSTONE_X86_SUPPORT "" ON)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/capstone ${CMAKE_CURRENT_BINARY_DIR}/capstone)

set(LLVM_TARGETS_TO_BUILD "AArch64;X86;ARM")
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/keystone ${CMAKE_CURRENT_BINARY_DIR}/keystone)

option(BUILD_SHARED_LIBS "" ON)

add_executable(ret
	lib/buffers.c
	lib/parser.c
	lib/re.c
)
target_include_directories(ret PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/keystone/include)
if(EMSCRIPTEN)
	target_link_libraries(ret PUBLIC capstone_static keystone
		-sEXPORTED_FUNCTIONS=_cli_asm_test,_re_init_globals,_re_assemble,_re_get_err_buffer,_re_get_hex_buffer,_re_get_str_buffer,_re_log,cwrap,_get_buffer_contents
		-sINVOKE_RUN=0
	)
else()
	target_link_libraries(ret PUBLIC capstone_static keystone)
endif()
