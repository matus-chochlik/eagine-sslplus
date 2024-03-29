# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt
#
find_package(OpenSSL REQUIRED)

target_link_libraries(
	eagine.sslplus
	INTERFACE ${OPENSSL_LIBRARIES}
)
