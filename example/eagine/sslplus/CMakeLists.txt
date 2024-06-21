# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt
#
add_custom_target(eagine-sslplus-examples ALL)
set_target_properties(
	eagine-sslplus-examples
	PROPERTIES FOLDER "Example/SSLplus"
)

function(eagine_install_example TARGET_NAME)
	install(
		TARGETS ${TARGET_NAME}
		COMPONENT sslplus-examples
		DESTINATION share/eagine/example/sslplus)
endfunction()

function(eagine_example_common EXAMPLE_NAME)
	add_executable(
		eagine-${EXAMPLE_NAME}
		EXCLUDE_FROM_ALL
		"${EXAMPLE_NAME}.cpp"
		${ARGN}
	)
	add_dependencies(eagine-sslplus-examples eagine-${EXAMPLE_NAME})
	eagine_add_exe_analysis(eagine-${EXAMPLE_NAME})
	target_compile_options(
		eagine-${EXAMPLE_NAME}
		PRIVATE $<$<BOOL:${EAGINE_CLANGXX_COMPILER}>:-Wno-unreachable-code>
	)
	eagine_target_modules(
		eagine-${EXAMPLE_NAME}
		std
		eagine.core
		eagine.sslplus
	)

	set_target_properties(
		eagine-${EXAMPLE_NAME}
		PROPERTIES FOLDER "Example/SSLplus"
	)
	eagine_install_example(eagine-${EXAMPLE_NAME})
endfunction()

configure_file(example-ca.crt example-ca.crt)
configure_file(example.crt example.crt)

eagine_example_common(001_log_ca_cert)
eagine_example_common(002_hash_self)
eagine_example_common(002_provider)
eagine_example_common(003_verify_cert)
eagine_example_common(004_verify_cert)
# eagine_example_common(005_random_engine)
# eagine_example_common(008_sign_self)
#
eagine_embed_target_resources(TARGET eagine-004_verify_cert)

eagine_add_license(sslplus-examples)
eagine_add_debian_changelog(sslplus-examples)

eagine_add_package_property(
	sslplus-examples
	GENERATOR DEBIAN
	VARIABLE PACKAGE_DEPENDS
	VALUE "\${CXX_RUNTIME_PKGS},\${EAGINE_CORE_RUNTIME_PKGS},\${EAGINE_SSLPLUS_RUNTIME_PKGS}")

eagine_add_package_property(
	sslplus-examples
	GENERATOR DEBIAN
	VARIABLE DESCRIPTION
	VALUE "EAGine SSLplus examples.")

