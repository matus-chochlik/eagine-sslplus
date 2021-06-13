/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSL_RESOURCES_HPP
#define EAGINE_SSL_RESOURCES_HPP

#include <eagine/main_ctx_fwd.hpp>
#include <eagine/memory/block.hpp>

namespace eagine {
//------------------------------------------------------------------------------
auto ca_certificate_pem(
  memory::const_block embedded_blk,
  memory::buffer&,
  application_config&,
  logger&) -> memory::const_block;
//------------------------------------------------------------------------------
auto ca_certificate_pem(memory::const_block embedded_blk, main_ctx& ctx)
  -> memory::const_block;
//------------------------------------------------------------------------------
auto ca_certificate_pem(main_ctx&) -> memory::const_block;
//------------------------------------------------------------------------------
} // namespace eagine

#if !EAGINE_SSL_LIBRARY || defined(EAGINE_IMPLEMENTING_LIBRARY)
#include <eagine/ssl/resources.inl>
#endif

#endif // EAGINE_SSL_RESOURCES_HPP

