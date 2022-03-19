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
  , object_to_text{"object_to_text", traits, *this}
  , cipher_update{"cipher_update", traits, *this}
  , cipher_final{"cipher_final", traits, *this}
  , cipher_final_ex{"cipher_final", traits, *this}
  , encrypt_update{"encrypt_update", traits, *this}
  , encrypt_final{"encrypt_final", traits, *this}
  , encrypt_final_ex{"encrypt_final", traits, *this}
  , decrypt_update{"decrypt_update", traits, *this}
  , decrypt_final{"decrypt_final", traits, *this}
  , decrypt_final_ex{"decrypt_final", traits, *this}
  , message_digest_final{"message_digest_final", traits, *this}
  , message_digest_final_ex{"message_digest_final", traits, *this}
  , message_digest_sign_init{"message_digest_sign_init", traits, *this}
  , message_digest_sign_final{"message_digest_sign_final", traits, *this}
  , message_digest_verify_init{"message_digest_verify_init", traits, *this}
  , read_bio_private_key{"read_bio_private_key", traits, *this}
  , read_bio_public_key{"read_bio_public_key", traits, *this}
  , read_bio_x509_crl{"read_bio_x509_crl", traits, *this}
  , read_bio_x509{"read_bio_x509", traits, *this} {}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
