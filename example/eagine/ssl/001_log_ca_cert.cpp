/// @example eagine/ssh/001_list_engines.cpp
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#include <eagine/logging/logger.hpp>
#include <eagine/main.hpp>
#include <eagine/sslplus/resources.hpp>

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {
    ctx.log()
      .info("embedded CA certificate")
      .arg(EAGINE_ID(arg), ca_certificate_pem(ctx));
    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine
