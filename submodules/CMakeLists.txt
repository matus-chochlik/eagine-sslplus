# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt
#
function(eagine_ensure_submodule_recursive SUBMODULE)
	if(NOT EXISTS ${SUBMODULE}/CMakeLists.txt)
		execute_process(
			COMMAND git submodule update --init --recursive
			${SUBMODULE}/CMakeLists.txt
		)
	endif()
	add_subdirectory(${SUBMODULE} ${SUBMODULE})
endfunction()

if(NOT TARGET EAGine::Core)
	set(
		EAGINE_EMBED_GENERATOR
		"python3"
		"${PROJECT_SOURCE_DIR}/submodules/eagine-core/config/tools/embed_generator"
	)
	eagine_ensure_submodule_recursive(eagine-core)
endif()
