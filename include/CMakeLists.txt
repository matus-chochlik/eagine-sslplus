# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt
#
configure_file(eagine/ssl_resources.gen.in eagine/ssl_resources.gen.inl @ONLY)
include(./Sources.cmake)
set(GEN_INLS eagine/ssl_resources.gen.inl)
# - regular headers ------------------------------------------------------------
add_library(eagine-ssl-headers INTERFACE)

target_include_directories(
	eagine-ssl-headers
	INTERFACE
		$<INSTALL_INTERFACE:include>
		$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

foreach(FILENAME ${HEADERS} ${PUB_INLS})
	set_property(
		TARGET eagine-ssl-headers
		APPEND PROPERTY PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/${FILENAME}
	)
endforeach()
# - private headers or implementation files ------------------------------------
add_library(eagine-ssl-private-headers INTERFACE)

target_include_directories(
	eagine-ssl-private-headers
	INTERFACE
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

foreach(FILENAME ${GEN_INLS})
	set_property(
		TARGET eagine-ssl-private-headers
		APPEND PROPERTY PRIVATE_HEADER ${CMAKE_CURRENT_BINARY_DIR}/${FILENAME}
	)
endforeach()
# - generated headers or implementation files ----------------------------------
add_library(eagine-ssl-generated-headers INTERFACE)

target_include_directories(
	eagine-ssl-generated-headers
	INTERFACE
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
)

foreach(FILENAME ${GEN_INLS})
	set_property(
		TARGET eagine-ssl-generated-headers
		APPEND PROPERTY PRIVATE_HEADER ${CMAKE_CURRENT_BINARY_DIR}/${FILENAME}
	)
endforeach()

