# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt
#
configure_file(
	eagine/sslplus/resources.gen.in
	eagine/sslplus/resources.gen.inl 
	@ONLY
)
set(GEN_INLS eagine/sslplus/resources.gen.inl)
include(./Sources.cmake)
# - regular headers ------------------------------------------------------------
add_library(eagine-sslplus-headers INTERFACE)

target_include_directories(
	eagine-sslplus-headers
	INTERFACE
		$<INSTALL_INTERFACE:include>
		$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

foreach(FILENAME ${HEADERS} ${PUB_INLS})
	set_property(
		TARGET eagine-sslplus-headers
		APPEND PROPERTY PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/${FILENAME}
	)
endforeach()
# - private headers or implementation files ------------------------------------
add_library(eagine-sslplus-private-headers INTERFACE)

target_include_directories(
	eagine-sslplus-private-headers
	INTERFACE
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

foreach(FILENAME ${GEN_INLS})
	set_property(
		TARGET eagine-sslplus-private-headers
		APPEND PROPERTY PRIVATE_HEADER ${CMAKE_CURRENT_BINARY_DIR}/${FILENAME}
	)
endforeach()
# - generated headers or implementation files ----------------------------------
add_library(eagine-sslplus-generated-headers INTERFACE)

target_include_directories(
	eagine-sslplus-generated-headers
	INTERFACE
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>
)

foreach(FILENAME ${GEN_INLS})
	set_property(
		TARGET eagine-sslplus-generated-headers
		APPEND PROPERTY PRIVATE_HEADER ${CMAKE_CURRENT_BINARY_DIR}/${FILENAME}
	)
endforeach()

