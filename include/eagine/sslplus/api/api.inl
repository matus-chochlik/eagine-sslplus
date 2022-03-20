/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
namespace eagine::sslplus {
//------------------------------------------------------------------------------
template <typename ApiTraits>
inline basic_ssl_operations<ApiTraits>::basic_ssl_operations(ApiTraits& traits)
  : ssl_api{traits}
  , message_digest_sign_final{"message_digest_sign_final", traits, *this}
  , message_digest_verify_init{"message_digest_verify_init", traits, *this}
  , read_bio_private_key{"read_bio_private_key", traits, *this}
  , read_bio_public_key{"read_bio_public_key", traits, *this}
  , read_bio_x509_crl{"read_bio_x509_crl", traits, *this}
  , read_bio_x509{"read_bio_x509", traits, *this} {}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
