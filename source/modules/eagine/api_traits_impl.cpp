/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
module;

#if __has_include(<openssl/conf.h>) && __has_include(<openssl/evp.h>)
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/ui.h>
#define EAGINE_HAS_SSL 1
#else
#define EAGINE_HAS_SSL 0
#endif

module eagine.sslplus;
import eagine.core.memory;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
auto ssl_api_traits ::_link_function(const string_view name) -> _any_fnptr_t {
#if EAGINE_HAS_SSL
#define EAGINE_GET_OPENSSL_FUNC(NAME)                 \
    if(name == #NAME) {                               \
        return reinterpret_cast<_any_fnptr_t>(&NAME); \
    }

    EAGINE_GET_OPENSSL_FUNC(ERR_get_error)
    // TODO: the remaining functions
#undef EAGINE_GET_OPENSSL_FUNC
#endif
    return nullptr;
}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
