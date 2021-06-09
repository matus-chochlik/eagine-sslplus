#  Copyright Matus Chochlik.
#  Distributed under the Boost Software License, Version 1.0.
#  See accompanying file LICENSE_1_0.txt or copy at
#   http://www.boost.org/LICENSE_1_0.txt
#
find_package(OpenSSL)

add_library(EAGine::SSL::Deps::OpenSSL INTERFACE IMPORTED)
if(OpenSSL_FOUND)
	if(OPENSSL_INCLUDE_DIRS)
		target_include_directories(
			EAGine::SSL::Deps::OpenSSL INTERFACE "${OPENSSL_INCLUDE_DIRS}"
		)
	endif()

	if(OPENSSL_LIBRARY_DIRS)
		set_target_properties(
			EAGine::SSL::Deps::OpenSSL PROPERTIES
			INTERFACE_LINK_DIRECTORIES "${OPENSSL_LIBRARY_DIRS}"
		)
	endif()

	target_compile_definitions(
		EAGine::SSL::Deps::OpenSSL INTERFACE EAGINE_USE_OPENSSL=1
	)

	target_link_libraries(
		EAGine::SSL::Deps::OpenSSL INTERFACE "${OPENSSL_LIBRARIES}"
	)
endif()

