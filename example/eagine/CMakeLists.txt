# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt

add_custom_target(eagine-ssl-examples ALL)
set_target_properties(
	eagine-ssl-examples
	PROPERTIES FOLDER "Example/SSL"
)

function(eagine_install_example TARGET_NAME)
	install(
		TARGETS ${TARGET_NAME}
		DESTINATION share/eagine/example/ssl
	)
endfunction()

function(eagine_example_common EXAMPLE_NAME)
	add_executable(
		eagine-${EXAMPLE_NAME}
		EXCLUDE_FROM_ALL
		"${EXAMPLE_NAME}.cpp"
		${ARGN}
	)
	eagine_add_exe_analysis(eagine-${EXAMPLE_NAME})
	add_dependencies(eagine-ssl-examples eagine-${EXAMPLE_NAME})
	target_link_libraries(
		eagine-${EXAMPLE_NAME}
		PUBLIC EAGine::SSL
		PRIVATE ${ARGN}
	)

	set_target_properties(
		eagine-${EXAMPLE_NAME}
		PROPERTIES FOLDER "Example/SSL"
	)
	eagine_install_example(eagine-${EXAMPLE_NAME})
endfunction()

add_subdirectory(ssl)
