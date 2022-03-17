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
  , copy_engine{"copy_engine", traits, *this}
  , init_engine{"init_engine", traits, *this}
  , finish_engine{"finish_engine", traits, *this}
  , load_engine_private_key{"load_engine_private_key", traits, *this}
  , get_int64{"get_int64", traits, *this}
  , get_uint64{"get_uint64", traits, *this}
  , object_to_text{"object_to_text", traits, *this}
  , random_bytes{"random_bytes", traits, *this}
  , new_cipher{"new_cipher", traits, *this}
  , cipher_reset{"cipher_reset", traits, *this}
  , cipher_init{"cipher_init", traits, *this}
  , cipher_init_ex{"cipher_init_ex", traits, *this}
  , cipher_update{"cipher_update", traits, *this}
  , cipher_final{"cipher_final", traits, *this}
  , cipher_final_ex{"cipher_final", traits, *this}
  , encrypt_init{"encrypt_init", traits, *this}
  , encrypt_init_ex{"encrypt_init_ex", traits, *this}
  , encrypt_update{"encrypt_update", traits, *this}
  , encrypt_final{"encrypt_final", traits, *this}
  , encrypt_final_ex{"encrypt_final", traits, *this}
  , decrypt_init{"decrypt_init", traits, *this}
  , decrypt_init_ex{"decrypt_init_ex", traits, *this}
  , decrypt_update{"decrypt_update", traits, *this}
  , decrypt_final{"decrypt_final", traits, *this}
  , decrypt_final_ex{"decrypt_final", traits, *this}
  , new_message_digest{"new_message_digest", traits, *this}
  , message_digest_reset{"message_digest_reset", traits, *this}
  , message_digest_init{"message_digest_init", traits, *this}
  , message_digest_init_ex{"message_digest_init_ex", traits, *this}
  , message_digest_update{"message_digest_update", traits, *this}
  , message_digest_final{"message_digest_final", traits, *this}
  , message_digest_final_ex{"message_digest_final", traits, *this}
  , message_digest_sign_init{"message_digest_sign_init", traits, *this}
  , message_digest_sign_update{"message_digest_sign_update", traits, *this}
  , message_digest_sign_final{"message_digest_sign_final", traits, *this}
  , message_digest_verify_init{"message_digest_verify_init", traits, *this}
  , message_digest_verify_update{"message_digest_verify_update", traits, *this}
  , message_digest_verify_final{"message_digest_verify_final", traits, *this}
  , new_x509_store_ctx{"new_x509_store_ctx", traits, *this}
  , init_x509_store_ctx{"init_x509_store_ctx", traits, *this}
  , set_x509_store_trusted_stack{"set_x509_store_trusted_stack", traits, *this}
  , set_x509_store_verified_chain{"set_x509_store_verified_chain", traits, *this}
  , set_x509_store_untrusted{"set_x509_store_untrusted", traits, *this}
  , x509_verify_certificate{"x509_verify_certificate", traits, *this}
  , new_x509_store{"new_x509_store", traits, *this}
  , copy_x509_store{"copy_x509_store", traits, *this}
  , add_cert_into_x509_store{"add_cert_into_x509_store", traits, *this}
  , add_crl_into_x509_store{"add_crl_into_x509_store", traits, *this}
  , load_into_x509_store{"load_into_x509_store", traits, *this}
  , new_x509_crl{"new_x509_crl", traits, *this}
  , new_x509{"new_x509", traits, *this}
  , get_x509_pubkey{"get_x509_pubkey", traits, *this}
  , get_x509_serial_number{"get_x509_serial_number", traits, *this}
  , get_x509_issuer_name{"get_x509_issuer_name", traits, *this}
  , get_x509_subject_name{"get_x509_subject_name", traits, *this}
  , get_name_entry_count{"get_name_entry_count", traits, *this}
  , get_name_entry{"get_name_entry", traits, *this}
  , get_name_entry_object{"get_name_entry_object", traits, *this}
  , get_name_entry_data{"get_name_entry_data", traits, *this}
  , read_bio_private_key{"read_bio_private_key", traits, *this}
  , read_bio_public_key{"read_bio_public_key", traits, *this}
  , read_bio_x509_crl{"read_bio_x509_crl", traits, *this}
  , read_bio_x509{"read_bio_x509", traits, *this} {}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
