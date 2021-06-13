# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt

add_library(
	eagine-ssl
	resources.cpp
)
eagine_embed_target_resources(
	TARGET eagine-ssl
	SCAN_TARGETS eagine-ssl-generated-headers
)
eagine_add_lib_analysis(eagine-ssl)

target_compile_definitions(
	eagine-ssl PUBLIC EAGINE_SSL_LIBRARY=1
)

target_include_directories(
	eagine-ssl
	PRIVATE
		"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)

target_link_libraries(
	eagine-ssl
	PUBLIC
		EAGine::SSL::Deps::OpenSSL
		EAGine::Core
		eagine-ssl-headers
	PRIVATE
		eagine-ssl-private-headers
		eagine-ssl-generated-headers
)
