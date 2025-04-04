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
	app/buffers.c
	app/parser.c
	app/re.c
)
target_include_directories(ret PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/keystone/include)
target_link_libraries(ret PUBLIC capstone_static keystone
	-sEXPORTED_FUNCTIONS=_cli_asm_test,_main,_re_log,_re_new,cwrap
	-sINVOKE_RUN=0
)
