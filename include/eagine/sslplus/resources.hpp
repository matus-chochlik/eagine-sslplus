/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_RESOURCES_HPP
#define EAGINE_SSLPLUS_RESOURCES_HPP

#include "config/basic.hpp"
#include <eagine/main_ctx_fwd.hpp>
#include <eagine/memory/block.hpp>

namespace eagine {
//------------------------------------------------------------------------------
auto ca_certificate_pem(
  const memory::const_block embedded_blk,
  memory::buffer&,
  application_config&,
  const logger&) noexcept -> memory::const_block;
//------------------------------------------------------------------------------
auto ca_certificate_pem(
  const memory::const_block embedded_blk,
  main_ctx& ctx) noexcept -> memory::const_block;
//------------------------------------------------------------------------------
auto ca_certificate_pem(main_ctx&) noexcept -> memory::const_block;
//------------------------------------------------------------------------------
} // namespace eagine

#if !EAGINE_SSLPLUS_LIBRARY || defined(EAGINE_IMPLEMENTING_SSLPLUS_LIBRARY)
#include <eagine/sslplus/resources.inl>
#endif

#endif // EAGINE_SSLPLUS_RESOURCES_HPP
