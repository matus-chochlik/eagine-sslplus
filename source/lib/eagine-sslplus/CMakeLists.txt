# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt

add_library(
	eagine-sslplus
	resources.cpp
)
eagine_embed_target_resources(
	TARGET eagine-sslplus
	SCAN_TARGETS eagine-sslplus-generated-headers
)
eagine_add_lib_analysis(eagine-sslplus)

target_compile_definitions(
	eagine-sslplus PUBLIC EAGINE_SSLPLUS_LIBRARY=1
)

target_include_directories(
	eagine-sslplus
	PRIVATE
		"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)

target_link_libraries(
	eagine-sslplus
	PUBLIC
		EAGine::SSLplus::Deps::OpenSSL
		EAGine::Core
		eagine-sslplus-headers
	PRIVATE
		eagine-sslplus-private-headers
		eagine-sslplus-generated-headers
)
