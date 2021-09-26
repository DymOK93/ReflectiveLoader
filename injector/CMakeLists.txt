find_package(WIL CONFIG REQUIRED)

add_executable(
	ReflectiveInjector
		injector.cpp	
		privilege_manager.cpp
)

target_compile_options(
	ReflectiveInjector PRIVATE 
		${BASIC_COMPILE_OPTIONS}
		$<$<CONFIG:Release>:${RELEASE_COMPILE_OPTIONS}>
)

target_link_libraries(
	ReflectiveInjector PRIVATE
		WIL::WIL 
		dll_payload
) 
