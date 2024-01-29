# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt
add_subdirectory(modules)

set(EAGINE_SSLPLUS_EXPORT_TARGETS)

if(TARGET eagine-sslplus)
	add_library(EAGine::SSLplus INTERFACE IMPORTED GLOBAL)
	target_link_libraries(
		EAGine::SSLplus
		INTERFACE
			eagine-sslplus-headers
			eagine-sslplus
	)

	list(
		APPEND EAGINE_SSLPLUS_EXPORT_TARGETS
			eagine-sslplus-generated-headers
			eagine-sslplus-private-headers
			eagine-sslplus-headers
			eagine-sslplus
	)

	install(
		EXPORT SSLplus
		NAMESPACE EAGine::
		FILE SSLplus.cmake
		DESTINATION lib/cmake/EAGine
	)
endif()

install(
	TARGETS ${EAGINE_SSLPLUS_EXPORT_TARGETS}
	EXPORT SSLplus
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
	RUNTIME DESTINATION bin
	INCLUDES DESTINATION include
	PUBLIC_HEADER DESTINATION include
)

