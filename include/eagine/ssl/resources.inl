/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#include <eagine/config/basic.hpp>
#include <eagine/resources.hpp>

namespace eagine {
//------------------------------------------------------------------------------
EAGINE_LIB_FUNC
auto ca_certificate_pem(
  memory::const_block embedded_blk,
  memory::buffer& buf,
  application_config& cfg,
  logger& log) -> memory::const_block {
    return fetch_resource(
      string_view{"CA certificate"},
      string_view{"ca_cert_path"},
      embedded_blk,
      buf,
      cfg,
      log);
}
//------------------------------------------------------------------------------
EAGINE_LIB_FUNC
auto ca_certificate_pem(memory::const_block embedded_blk, main_ctx& ctx)
  -> memory::const_block {
    return ca_certificate_pem(
      embedded_blk, ctx.scratch_space(), ctx.config(), ctx.log());
}
//------------------------------------------------------------------------------
} // namespace eagine
#include <eagine/ssl/resources.gen.inl>

