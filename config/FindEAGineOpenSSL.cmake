#  Copyright Matus Chochlik.
#  Distributed under the Boost Software License, Version 1.0.
#  See accompanying file LICENSE_1_0.txt or copy at
#  https://www.boost.org/LICENSE_1_0.txt
#
find_package(OpenSSL)

add_library(EAGine::SSLplus::Deps::OpenSSL INTERFACE IMPORTED)
if(OpenSSL_FOUND)
	if(OPENSSL_INCLUDE_DIRS)
		target_include_directories(
			EAGine::SSLplus::Deps::OpenSSL INTERFACE "${OPENSSL_INCLUDE_DIRS}"
		)
	endif()

	if(OPENSSL_LIBRARY_DIRS)
		set_target_properties(
			EAGine::SSLplus::Deps::OpenSSL PROPERTIES
			INTERFACE_LINK_DIRECTORIES "${OPENSSL_LIBRARY_DIRS}"
		)
	endif()

	target_link_libraries(
		EAGine::SSLplus::Deps::OpenSSL INTERFACE "${OPENSSL_LIBRARIES}"
	)
endif()

