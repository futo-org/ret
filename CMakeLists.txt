# cmake -G Ninja -B build_em -DCMAKE_TOOLCHAIN_FILE=/home/daniel/dotfiles/emscripten2.cmake -DCMAKE_BUILD_TYPE=Release
cmake_minimum_required(VERSION 3.10)
project(fudge)

option(UNICORN_SUPPORT "" ON)
option(SUPPORT_ARM64 "" ON)
option(SUPPORT_ARM32 "" ON)
option(SUPPORT_X86 "" ON)

set(CMAKE_C_FLAGS_RELEASE -O3)
set(CMAKE_CXX_FLAGS_RELEASE -O3)

# Import capstone disassembly framework
option(BUILD_LIBS_ONLY "" ON)
option(BUILD_SHARED_LIBS "" OFF)
option(CAPSTONE_ARCHITECTURE_DEFAULT "" OFF)
if(SUPPORT_ARM32)
	option(CAPSTONE_ARM_SUPPORT "" ON)
else()
	option(CAPSTONE_ARM_SUPPORT "" OFF)
endif()
if(SUPPORT_ARM64)
	option(CAPSTONE_AARCH64_SUPPORT "" ON)
else()
	option(CAPSTONE_AARCH64_SUPPORT "" OFF)
endif()
if(SUPPORT_X86)
	option(CAPSTONE_X86_SUPPORT "" ON)
else()
	option(CAPSTONE_X86_SUPPORT "" OFF)
endif()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/capstone ${CMAKE_CURRENT_BINARY_DIR}/capstone)

# Import keystone assembler
set(LLVM_TARGETS_TO_BUILD "")
if(SUPPORT_ARM64)
	list(APPEND LLVM_TARGETS_TO_BUILD AArch64)
endif()
if(SUPPORT_ARM64)
	list(APPEND LLVM_TARGETS_TO_BUILD ARM)
endif()
if(SUPPORT_X86)
	list(APPEND LLVM_TARGETS_TO_BUILD X86)
endif()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/keystone ${CMAKE_CURRENT_BINARY_DIR}/keystone)

if(UNICORN_SUPPORT)
	set(UNICORN_ARCH "aarch64" CACHE STRING "Supported architectures")
	option(BUILD_SHARED_LIBS "" OFF)
	option(UNICORN_BUILD_SAMPLES "" OFF)
	option(UNICORN_INSTALL "" OFF)
	add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../unicorn-wasm ${CMAKE_CURRENT_BINARY_DIR}/unicorn)
	# TODO
endif()

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
