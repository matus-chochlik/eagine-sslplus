# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt

eagine_add_module(
	eagine.sslplus PARTITION config
	IMPORTS eagine.core.types
)

eagine_add_module(
	eagine.sslplus PARTITION result
	IMPORTS
		eagine.core.types
		eagine.core.memory
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus PARTITION object_handle
	IMPORTS
		config
		eagine.core.identifier
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus PARTITION object_stack
	IMPORTS
		config
		object_handle
		eagine.core.types
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus PARTITION api_traits
	IMPORTS
		result
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus PARTITION c_api
	IMPORTS
		config api_traits result
		eagine.core.types
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus PARTITION constants
	IMPORTS c_api
)

eagine_add_module(
	eagine.sslplus PARTITION api
	IMPORTS
		config api_traits result
		object_handle object_stack
		c_api constants
		eagine.core.types
		eagine.core.memory
		eagine.core.string
		eagine.core.utility
		eagine.core.c_api
)

eagine_add_module(
	eagine.sslplus PARTITION resources
	IMPORTS
		eagine.core.types
		eagine.core.memory
		eagine.core.main_ctx
		eagine.core.resource
)

eagine_add_module(
	eagine.sslplus
	PP_NAME SSLPLUS
	INTERFACES sslplus
	PARTITIONS
		config
		result
		object_handle
		object_stack
		api_traits
		c_api
		constants
		api
		resources
	SOURCES
)

