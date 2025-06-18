# cmake -G Ninja -B build_em -DCMAKE_TOOLCHAIN_FILE=/home/daniel/dotfiles/emscripten2.cmake -DCMAKE_BUILD_TYPE=Release
cmake_minimum_required(VERSION 3.10)
project(fudge)

option(UNICORN_SUPPORT "" ON)
option(SUPPORT_ARM64 "" OFF)
option(SUPPORT_ARM32 "" OFF)
option(SUPPORT_X86 "" OFF)

if(NOT SUPPORT_ARM64 AND NOT SUPPORT_ARM32 AND NOT SUPPORT_X86)
	message(FATAL_ERROR "at least one arch required ${SUPPORT_ARM64} ${SUPPORT_ARM32} ${SUPPORT_X86}")
endif()

set(CMAKE_C_FLAGS_RELEASE -Os)
set(CMAKE_CXX_FLAGS_RELEASE -Os)

set(RET_DEFINES "")

# Import capstone disassembly framework
option(BUILD_LIBS_ONLY "" ON)
option(BUILD_SHARED_LIBS "" OFF)
option(CAPSTONE_ARCHITECTURE_DEFAULT "" OFF)
if(SUPPORT_ARM32)
	option(CAPSTONE_ARM_SUPPORT "" ON)
	set(RET_DEFINES ${RET_DEFINES} -DRET_SUPPORT_ARM32=1)
else()
	option(CAPSTONE_ARM_SUPPORT "" OFF)
endif()
if(SUPPORT_ARM64)
	option(CAPSTONE_AARCH64_SUPPORT "" ON)
	set(RET_DEFINES ${RET_DEFINES} -DRET_SUPPORT_ARM64=1)
else()
	option(CAPSTONE_AARCH64_SUPPORT "" OFF)
endif()
if(SUPPORT_X86)
	option(CAPSTONE_X86_SUPPORT "" ON)
	set(RET_DEFINES ${RET_DEFINES} -DRET_SUPPORT_X86=1)
else()
	option(CAPSTONE_X86_SUPPORT "" OFF)
endif()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/capstone ${CMAKE_CURRENT_BINARY_DIR}/capstone)

# Import keystone assembler
set(temp_targets)
if(SUPPORT_ARM64)
	list(APPEND temp_targets AArch64)
endif()
if(SUPPORT_ARM32)
	list(APPEND temp_targets ARM)
endif()
if(SUPPORT_X86)
	list(APPEND temp_targets X86)
endif()
set(LLVM_TARGETS_TO_BUILD "${temp_targets}" CACHE STRING "Targets to build" FORCE)
option(BUILD_LIBS_ONLY "Only build keystone library" 1)
set(CMAKE_CROSSCOMPILING OFF) # Fix weird issue where keystone tries to configure top level again (???)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/keystone ${CMAKE_CURRENT_BINARY_DIR}/keystone)

if(UNICORN_SUPPORT)
	set(UNICORN_ARCH "aarch64" CACHE STRING "Supported architectures")
	option(BUILD_SHARED_LIBS "" OFF)
	option(UNICORN_BUILD_SAMPLES "" OFF)
	option(UNICORN_INSTALL "" OFF)
	option(UNICORN_INTERPRETER "Use interpreter mode" ON)
	add_subdirectory(/home/daniel/Pulled/unicorn ${CMAKE_CURRENT_BINARY_DIR}/unicorn)
endif()

add_executable(ret
	lib/buffers.c
	lib/parser.c
	lib/re.c
	$<$<BOOL:${UNICORN_SUPPORT}>:lib/unicorn.c>
)

target_include_directories(ret PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/keystone/include)
target_compile_definitions(ret PRIVATE ${RET_DEFINES})
if(EMSCRIPTEN)
	target_link_libraries(ret PUBLIC capstone_static keystone $<$<BOOL:${UNICORN_SUPPORT}>:unicorn>
		-sEXPORTED_FUNCTIONS=_cli_asm_test,_re_init_globals,_re_assemble,_re_disassemble,_re_get_err_buffer,_re_get_hex_buffer,_re_get_str_buffer,_re_log,cwrap,_get_buffer_contents,_emulator
		-sINVOKE_RUN=0
		-sALLOW_MEMORY_GROWTH
		-sALLOW_TABLE_GROWTH
		-sEXPORTED_RUNTIME_METHODS=addFunction
	)
else()
	target_link_libraries(ret PUBLIC capstone_static keystone $<$<BOOL:${UNICORN_SUPPORT}>:unicorn>)
endif()
