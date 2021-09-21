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
  : c_api{traits}
  , null_ui{"null_ui", traits, *this}
  , openssl_ui{"openssl_ui", traits, *this}
  , load_builtin_engines{"load_builtin_engines", traits, *this}
  , get_first_engine{"get_first_engine", traits, *this}
  , get_last_engine{"get_last_engine", traits, *this}
  , get_next_engine{"get_next_engine", traits, *this}
  , get_prev_engine{"get_prev_engine", traits, *this}
  , new_engine{"new_engine", traits, *this}
  , open_engine{"open_engine", traits, *this}
  , copy_engine{"copy_engine", traits, *this}
  , delete_engine{"delete_engine", traits, *this}
  , init_engine{"init_engine", traits, *this}
  , finish_engine{"finish_engine", traits, *this}
  , get_engine_id{"get_engine_id", traits, *this}
  , get_engine_name{"get_engine_name", traits, *this}
  , set_default_rsa{"set_default_rsa", traits, *this}
  , set_default_dsa{"set_default_dsa", traits, *this}
  , set_default_dh{"set_default_dh", traits, *this}
  , set_default_rand{"set_default_rand", traits, *this}
  , set_default_ciphers{"set_default_ciphers", traits, *this}
  , set_default_digests{"set_default_digests", traits, *this}
  , load_engine_private_key{"load_engine_private_key", traits, *this}
  , load_engine_public_key{"load_engine_public_key", traits, *this}
  , get_string_length{"get_string_length", traits, *this}
  , get_string_data{"get_string_data", traits, *this}
  , get_int64{"get_int64", traits, *this}
  , get_uint64{"get_uint64", traits, *this}
  , object_to_text{"object_to_text", traits, *this}
  , new_basic_io{"new_basic_io", traits, *this}
  , new_block_basic_io{"new_block_basic_io", traits, *this}
  , delete_basic_io{"delete_basic_io", traits, *this}
  , delete_all_basic_ios{"delete_all_basic_ios", traits, *this}
  , random_bytes{"random_bytes", traits, *this}
  , copy_pkey{"copy_pkey", traits, *this}
  , delete_pkey{"delete_pkey", traits, *this}
  , cipher_aes_128_ctr{"cipher_aes_128_ctr", traits, *this}
  , cipher_aes_128_ccm{"cipher_aes_128_ccm", traits, *this}
  , cipher_aes_128_gcm{"cipher_aes_128_gcm", traits, *this}
  , cipher_aes_128_xts{"cipher_aes_128_xts", traits, *this}
  , cipher_aes_192_ecb{"cipher_aes_192_ecb", traits, *this}
  , cipher_aes_192_cbc{"cipher_aes_192_cbc", traits, *this}
  , new_cipher{"new_cipher", traits, *this}
  , delete_cipher{"delete_cipher", traits, *this}
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
  , message_digest_noop{"message_digest_noop", traits, *this}
  , message_digest_md5{"message_digest_md5", traits, *this}
  , message_digest_sha1{"message_digest_sha1", traits, *this}
  , message_digest_sha224{"message_digest_sha224", traits, *this}
  , message_digest_sha256{"message_digest_sha256", traits, *this}
  , message_digest_sha384{"message_digest_sha384", traits, *this}
  , message_digest_sha512{"message_digest_sha512", traits, *this}
  , message_digest_size{"message_digest_size", traits, *this}
  , new_message_digest{"new_message_digest", traits, *this}
  , delete_message_digest{"delete_message_digest", traits, *this}
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
  , cleanup_x509_store_ctx{"cleanup_x509_store_ctx", traits, *this}
  , delete_x509_store_ctx{"delete_x509_store_ctx", traits, *this}
  , x509_verify_certificate{"x509_verify_certificate", traits, *this}
  , new_x509_store{"new_x509_store", traits, *this}
  , copy_x509_store{"copy_x509_store", traits, *this}
  , delete_x509_store{"delete_x509_store", traits, *this}
  , add_cert_into_x509_store{"add_cert_into_x509_store", traits, *this}
  , add_crl_into_x509_store{"add_crl_into_x509_store", traits, *this}
  , load_into_x509_store{"load_into_x509_store", traits, *this}
  , new_x509_crl{"new_x509_crl", traits, *this}
  , delete_x509_crl{"delete_x509_crl", traits, *this}
  , new_x509{"new_x509", traits, *this}
  , get_x509_pubkey{"get_x509_pubkey", traits, *this}
  , get_x509_serial_number{"get_x509_serial_number", traits, *this}
  , get_x509_issuer_name{"get_x509_issuer_name", traits, *this}
  , get_x509_subject_name{"get_x509_subject_name", traits, *this}
  , delete_x509{"delete_x509", traits, *this}
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
