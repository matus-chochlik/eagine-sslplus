/// @example eagine/sslplus/001_log_ca_cert.cpp
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#if EAGINE_SSLPLUS_MODULE
import eagine.core;
import eagine.sslplus;
#else
#include <eagine/logging/logger.hpp>
#include <eagine/main_ctx.hpp>
#include <eagine/sslplus/resources.hpp>
#endif

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {
    ctx.log()
      .info("embedded CA certificate")
      .arg(identifier{"arg"}, ca_certificate_pem(ctx));
    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine

auto main(int argc, const char** argv) -> int {
    return eagine::default_main(argc, argv, eagine::main);
}

