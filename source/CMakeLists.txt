# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt
if(${WITH_MODULES})
	add_subdirectory(modules)
else()
	add_subdirectory(lib)
endif()

if(TARGET eagine-sslplus)
	add_library(EAGine::SSLplus INTERFACE IMPORTED GLOBAL)
	target_link_libraries(EAGine::SSLplus INTERFACE eagine-sslplus-headers)

	target_link_libraries(
		EAGine::SSLplus
		INTERFACE
			eagine-sslplus
	)

	install(
		TARGETS
			eagine-sslplus-generated-headers
			eagine-sslplus-private-headers
			eagine-sslplus-headers
			eagine-sslplus
		EXPORT SSLplus
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
		RUNTIME DESTINATION bin
		INCLUDES DESTINATION include
		PUBLIC_HEADER DESTINATION include
	)

	install(
		EXPORT SSLplus
		NAMESPACE EAGine::
		FILE SSLplus.cmake
		DESTINATION lib/cmake/EAGine
	)
endif()
