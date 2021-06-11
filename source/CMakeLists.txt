# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt
add_subdirectory(lib)

add_library(EAGine::SSL INTERFACE IMPORTED GLOBAL)
target_link_libraries(EAGine::SSL INTERFACE eagine-ssl-headers)

target_link_libraries(
	EAGine::SSL
	INTERFACE
		eagine-ssl
)

get_target_property(EAGINE_CORE_LIBS EAGine::Core INTERFACE_LINK_LIBRARIES)

install(
	TARGETS
		eagine-ssl-generated-headers
		eagine-ssl-headers
		eagine-ssl
	EXPORT SSL
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	RUNTIME DESTINATION bin
	INCLUDES DESTINATION include
	PUBLIC_HEADER DESTINATION include
)

install(
	EXPORT SSL
	NAMESPACE EAGine::
	FILE SSL.cmake
	DESTINATION lib/cmake/EAGine
)
