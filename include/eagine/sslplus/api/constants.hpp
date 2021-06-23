/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_CONSTANTS_HPP
#define EAGINE_SSLPLUS_API_CONSTANTS_HPP

#include "c_api.hpp"

namespace eagine::sslplus {
//------------------------------------------------------------------------------
template <typename ApiTraits>
struct basic_ssl_constants {
public:
    basic_ssl_constants(ApiTraits&, basic_ssl_c_api<ApiTraits>&) {}
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif // EAGINE_SSLPLUS_API_CONSTANTS_HPP
