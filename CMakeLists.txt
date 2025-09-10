cmake_minimum_required(VERSION 3.10)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(fudge)
if(EMSCRIPTEN)
	# Speed up cmake checks on emscripten
	set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
	set(CMAKE_REQUIRED_FLAGS "-sSIDE_MODULE=1 -sWASM=1 -sERROR_ON_UNDEFINED_SYMBOLS=0")
endif()

option(SUPPORT_ALL "Support all architectures" OFF)
option(SUPPORT_ARM64 "arm v8+" OFF)
option(SUPPORT_ARM32 "arm and arm thumb" OFF)
option(SUPPORT_X86 "x86 and x86_64" OFF)
option(SUPPORT_RISCV "rv64 and rv32" OFF)
option(USE_UNICORN_WASM "Use older unicorn-wasm branch instead of Unicorn2" OFF)
if(SUPPORT_ALL)
	set(SUPPORT_ARM64 ON CACHE BOOL "" FORCE)
	set(SUPPORT_ARM32 ON CACHE BOOL "" FORCE)
	set(SUPPORT_X86 ON CACHE BOOL "" FORCE)
	set(SUPPORT_RISCV ON CACHE BOOL "" FORCE)
endif()
if(EMSCRIPTEN)
	option(SUPPORT_MULTITHREADING "Support emscripten multithreading" OFF)
endif()

if(NOT SUPPORT_ARM64 AND NOT SUPPORT_ARM32 AND NOT SUPPORT_X86 AND NOT SUPPORT_RISCV)
	message(FATAL_ERROR "at least one arch required")
endif()

set(CMAKE_C_FLAGS_RELEASE -Os)
set(CMAKE_CXX_FLAGS_RELEASE -Os)
set(CMAKE_C_FLAGS_DEBUG -g)
set(CMAKE_CXX_FLAGS_DEBUG -g)
set(CMAKE_C_FLAGS_RELWITHDEBUG -g)
set(CMAKE_CXX_FLAGS_RELWITHDEBUG -g)

if(EMSCRIPTEN AND SUPPORT_MULTITHREADING)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -matomics -mbulk-memory")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -matomics -mbulk-memory")
endif()

set(RET_DEFINES "")
set(RET_DEFINES ${RET_DEFINES} -DRET_SUPPORT_UNICORN=1)

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
if(SUPPORT_RISCV)
	option(CAPSTONE_RISCV_SUPPORT "" ON)
	set(RET_DEFINES ${RET_DEFINES} -DRET_SUPPORT_RISCV=1)
else()
	option(CAPSTONE_RISCV_SUPPORT "" OFF)
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
if(SUPPORT_RISCV)
	list(APPEND temp_targets RISCV)
endif()
set(LLVM_TARGETS_TO_BUILD "${temp_targets}" CACHE STRING "Targets to build" FORCE)
option(BUILD_LIBS_ONLY "Only build keystone library" 1)
set(CMAKE_CROSSCOMPILING OFF) # Fix weird issue where keystone tries to configure top level again (???)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/keystone ${CMAKE_CURRENT_BINARY_DIR}/keystone)

if(USE_UNICORN_WASM)
	set(temp_targets "")
	if(SUPPORT_ARM64)
		set(temp_targets "${temp_targets} AArch64")
	endif()
	if(SUPPORT_ARM32)
		set(temp_targets "${temp_targets} ARM")
	endif()
	if(SUPPORT_X86)
		set(temp_targets "${temp_targets} X86")
	endif()
	# Note: No risc support yet
	set(UNICORN_ARCH ${temp_targets} CACHE STRING "Supported architectures")
	option(BUILD_SHARED_LIBS "" OFF)
	option(UNICORN_BUILD_SAMPLES "" OFF)
	option(UNICORN_INSTALL "" OFF)
	add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/unicorn-wasm ${CMAKE_CURRENT_BINARY_DIR}/unicorn)	
else()
	set(temp_targets)
	if(SUPPORT_ARM64)
		list(APPEND temp_targets aarch64)
	endif()
	if(SUPPORT_ARM32)
		list(APPEND temp_targets arm)
	endif()
	if(SUPPORT_X86)
		list(APPEND temp_targets x86)
	endif()
	if(SUPPORT_RISCV)
		list(APPEND temp_targets riscv)
	endif()

	set(UNICORN_ARCH ${temp_targets} CACHE STRING "Supported architectures" FORCE)
	option(BUILD_SHARED_LIBS "" OFF)
	option(UNICORN_BUILD_SAMPLES "" OFF)
	option(UNICORN_INSTALL "" OFF)
	option(UNICORN_INTERPRETER "Use interpreter mode" ON)
	add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/unicorn ${CMAKE_CURRENT_BINARY_DIR}/unicorn)
endif()

add_executable(ret
	lib/buffers.c
	lib/parser.c
	lib/re.c
	lib/unicorn.c
)

set(EXPORT_FUNCS _re_is_arch_supported,_re_init_globals,_re_assemble,_re_disassemble,_re_get_err_buffer,_re_get_hex_buffer,_re_get_str_buffer,_re_get_mem_buffer,_buffer_get_contents,_parser_to_buf,_re_is_unicorn_supported,_buffer_to_buffer,_buffer_get_data_length,_re_get_hex_mem_mirror_buffer,_re_emulator)

target_include_directories(ret PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/keystone/include)
target_compile_definitions(ret PRIVATE ${RET_DEFINES})
if(EMSCRIPTEN)
	target_link_libraries(ret PUBLIC capstone_static keystone unicorn
		-sIGNORE_MISSING_MAIN
		-sEXPORTED_FUNCTIONS=${EXPORT_FUNCS}
		-sINVOKE_RUN=0
		-SDYNCALLS=1
		$<$<VERSION_LESS_EQUAL:${EMSCRIPTEN_VERSION},3.1.69>:-sUSE_OFFSET_CONVERTER>
		-sALLOW_MEMORY_GROWTH
		-sALLOW_TABLE_GROWTH
		-sEXPORTED_RUNTIME_METHODS=addFunction,ccall,cwrap
		$<$<BOOL:${SUPPORT_MULTITHREADING}>:-sUSE_PTHREADS=1 -sPTHREAD_POOL_SIZE=2 -pthread>
		-gsource-map
	)
else()
	target_link_libraries(ret PUBLIC capstone_static keystone unicorn)
endif()
