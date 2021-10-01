cmake_minimum_required (VERSION 3.19)
cmake_policy(SET CMP0091 NEW)	# For CMAKE_MSVC_RUNTIME_LIBRARY
project ("ReflectiveLoader")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY  "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/exe")

set(
	BASIC_COMPILE_OPTIONS
		/MP	# Multiprocessor compilation
		/W4 # Warnings level
		/WX # Treat warnings as errors
)
set(
	RELEASE_COMPILE_OPTIONS
		/O2		# Max optimization level
		/Ob3	# Aggressive inlining
		/Oi     # Enable intrinsics
		/Ot     # Prefer fast code
		/Oy		# Omit frame pointers
)

add_subdirectory(cmrc)
add_subdirectory(injector)
add_subdirectory(payload)

cmrc_add_resource_library(
	dll_payload 
		WHENCE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} 
		${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/ReflectiveDLL.dll 
)