set(DLL_ADDITIONAL_FLAGS_FILE "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/dllflags.h")
file(WRITE ${DLL_ADDITIONAL_FLAGS_FILE} "#pragma runtime_checks(\"suc\", off)")

add_library(
	ReflectiveDLL SHARED
		loader.cpp
		payload.cpp	
)

target_compile_options(
	ReflectiveDLL PRIVATE 
		${BASIC_COMPILE_OPTIONS}
		$<$<CONFIG:Release>:${RELEASE_COMPILE_OPTIONS}>
		/EHsc-
		/GR-
		"/FI${DLL_ADDITIONAL_FLAGS_FILE}" # include file to disable RTC
)

target_link_options(
	ReflectiveDLL PRIVATE 
		${NATIVE_LINK_OPTIONS}
		/MANIFEST:NO
		/NODEFAULTLIB                     # no CRT, STL, etc.
		/SUBSYSTEM:Windows
		/ENTRY:DllMain
)