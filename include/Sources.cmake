# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt
#
set(HEADERS
    eagine/sslplus/api/api.hpp
    eagine/sslplus/api/api_traits.hpp
    eagine/sslplus/api/c_api.hpp
    eagine/sslplus/api/config.hpp
    eagine/sslplus/api/constants.hpp
    eagine/sslplus/api_fwd.hpp
    eagine/sslplus/api.hpp
    eagine/sslplus/api/object_handle.hpp
    eagine/sslplus/api/object_stack.hpp
    eagine/sslplus/api/result.hpp
    eagine/sslplus/openssl.hpp
    eagine/sslplus/resources.hpp
)

set(PUB_INLS
    eagine/sslplus/api/c_api.inl
    eagine/sslplus/api/api.inl
    eagine/sslplus/api.inl
)

set(LIB_INLS
    eagine/sslplus/resources.inl
)

