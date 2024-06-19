# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt
configure_file(embedded.cpp.in embedded.cppm @ONLY)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION config
	IMPORTS
		std
		eagine.core.types
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION result
	IMPORTS
		std
		eagine.core.types
		eagine.core.memory
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION object_handle
	IMPORTS
		std config
		eagine.core.identifier
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION object_stack
	IMPORTS
		std config
		object_handle
		eagine.core.types
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION api_traits
	IMPORTS
		std result
		eagine.core.memory
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION c_api
	IMPORTS
		std config
		api_traits result
		eagine.core.types
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION constants
	IMPORTS
		std c_api
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION api
	IMPORTS
		std config api_traits result
		object_handle object_stack
		c_api constants
		eagine.core.types
		eagine.core.memory
		eagine.core.string
		eagine.core.utility
		eagine.core.c_api
		eagine.core.main_ctx
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION resources
	IMPORTS
		std
		eagine.core
)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	PARTITION embedded
	IMPORTS
		std resources
		eagine.core
)
eagine_embed_target_resources(TARGET eagine.sslplus)

eagine_add_module(
	eagine.sslplus
	COMPONENT sslplus-dev
	SOURCES
		api_traits
		object_stack
	IMPORTS
		std
		eagine.core.resource
		eagine.core.memory
		eagine.core
)
target_link_libraries(
	eagine.sslplus
	PUBLIC
		EAGine::SSLplus::Deps::OpenSSL
)

eagine_add_license(sslplus-dev)
eagine_add_debian_changelog(sslplus-dev)

eagine_add_package_property(
	sslplus-dev
	GENERATOR DEBIAN
	VARIABLE PACKAGE_DEPENDS
	VALUE "eagine-core-dev (>= @EAGINE_VERSION@),libssl-dev")

eagine_add_package_property(
	sslplis-dev
	GENERATOR DEBIAN
	VARIABLE DESCRIPTION
	VALUE "C++ wrapper for OpenSSL.")

