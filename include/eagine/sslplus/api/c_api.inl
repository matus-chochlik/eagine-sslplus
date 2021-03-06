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
inline basic_ssl_c_api<ApiTraits>::basic_ssl_c_api(ApiTraits& traits)
  : _traits{traits}
  , err_get_error{"ERR_get_error", *this}
  , err_peek_error{"ERR_peek_error", *this}
  , err_error_string_n{"ERR_error_string_n", *this}
  , ui_null{"UI_null", *this}
  , ui_openssl{"UI_OpenSSL", *this}
  , ui_get_default_method{"UI_get_default_method", *this}
  , asn1_string_length{"ASN1_STRING_length", *this}
  , asn1_string_get0_data{"ASN1_STRING_get0_data", *this}
  , asn1_integer_get_int64{"ASN1_INTEGER_get_int64", *this}
  , asn1_integer_get_uint64{"ASN1_INTEGER_get_uint64", *this}
  , obj_obj2txt{"OBJ_obj2txt", *this}
  , bio_new{"BIO_new", *this}
  , bio_new_mem_buf{"BIO_new_mem_buf", *this}
  , bio_up_ref{"BIO_up_ref", *this}
  , bio_free{"BIO_free", *this}
  , bio_free_all{"BIO_free_all", *this}
  , rand_bytes{"RAND_bytes", *this}
  , evp_pkey_new{"EVP_PKEY_new", *this}
  , evp_pkey_up_ref{"EVP_PKEY_up_ref", *this}
  , evp_pkey_free{"EVP_PKEY_free", *this}
  , evp_aes_128_ctr{"evp_aes_128_ctr", *this}
  , evp_aes_128_ccm{"evp_aes_128_ccm", *this}
  , evp_aes_128_gcm{"evp_aes_128_gcm", *this}
  , evp_aes_128_xts{"evp_aes_128_xts", *this}
  , evp_aes_192_ecb{"evp_aes_192_ecb", *this}
  , evp_aes_192_cbc{"evp_aes_192_cbc", *this}
  , evp_cipher_ctx_new{"EVP_CIPHER_CTX_new", *this}
  , evp_cipher_ctx_reset{"EVP_CIPHER_CTX_reset", *this}
  , evp_cipher_ctx_free{"EVP_CIPHER_CTX_free", *this}
  , evp_cipher_init{"EVP_CipherInit", *this}
  , evp_cipher_init_ex{"EVP_CipherInit_ex", *this}
  , evp_cipher_update{"EVP_CipherUpdate", *this}
  , evp_cipher_final{"EVP_CipherFinal", *this}
  , evp_cipher_final_ex{"EVP_CipherFinal_ex", *this}
  , evp_encrypt_init{"EVP_EncryptInit", *this}
  , evp_encrypt_init_ex{"EVP_EncryptInit_ex", *this}
  , evp_encrypt_update{"EVP_EncryptUpdate", *this}
  , evp_encrypt_final{"EVP_EncryptFinal", *this}
  , evp_encrypt_final_ex{"EVP_EncryptFinal_ex", *this}
  , evp_decrypt_init{"EVP_DecryptInit", *this}
  , evp_decrypt_init_ex{"EVP_DecryptInit_ex", *this}
  , evp_decrypt_update{"EVP_DecryptUpdate", *this}
  , evp_decrypt_final{"EVP_DecryptFinal", *this}
  , evp_decrypt_final_ex{"EVP_DecryptFinal_ex", *this}
  , evp_md_null{"EVP_md_null", *this}
  , evp_md5{"EVP_md5", *this}
  , evp_sha1{"EVP_sha1", *this}
  , evp_sha224{"EVP_sha224", *this}
  , evp_sha256{"EVP_sha256", *this}
  , evp_sha384{"EVP_sha384", *this}
  , evp_sha512{"EVP_sha512", *this}
  , evp_get_digest_by_name{"EVP_get_digestbyname", *this}
  , evp_md_size{"EVP_MD_size", *this}
  , evp_md_block_size{"EVP_MD_block_size", *this}
  , evp_md_ctx_new{"EVP_MD_CTX_new", *this}
  , evp_md_ctx_reset{"EVP_MD_CTX_reset", *this}
  , evp_md_ctx_free{"EVP_MD_CTX_free", *this}
  , evp_digest_init{"EVP_DigestInit", *this}
  , evp_digest_init_ex{"EVP_DigestInit_ex", *this}
  , evp_digest_update{"EVP_DigestUpdate", *this}
  , evp_digest_final{"EVP_DigestFinal", *this}
  , evp_digest_final_ex{"EVP_DigestFinal_ex", *this}
  , evp_digest_sign_init{"EVP_DigestSignInit", *this}
  , evp_digest_sign_update{"EVP_DigestSignUpdate", *this}
  , evp_digest_sign_final{"EVP_DigestSignFinal", *this}
  , evp_digest_verify_init{"EVP_DigestVerifyInit", *this}
  , evp_digest_verify_update{"EVP_DigestVerifyUpdate", *this}
  , evp_digest_verify_final{"EVP_DigestVerifyFinal", *this}
  , x509_lookup_hash_dir{"X509_LOOKUP_hash_dir", *this}
  , x509_lookup_file{"X509_LOOKUP_file", *this}
  , x509_store_ctx_new{"X509_STORE_CTX_new", *this}
  , x509_store_ctx_init{"X509_STORE_CTX_init", *this}
  , x509_store_ctx_set0_trusted_stack{"X509_STORE_CTX_set0_trusted_stack", *this}
  , x509_store_ctx_set0_verified_chain{"X509_STORE_CTX_set0_verified_chain", *this}
  , x509_store_ctx_set0_untrusted{"X509_STORE_CTX_set0_untrusted", *this}
  , x509_store_ctx_cleanup{"X509_STORE_CTX_cleanup", *this}
  , x509_store_ctx_free{"X509_STORE_CTX_free", *this}
  , x509_verify_cert{"X509_verify_cert", *this}
  , x509_store_new{"X509_STORE_new", *this}
  , x509_store_up_ref{"X509_STORE_up_ref", *this}
  , x509_store_lock{"X509_STORE_lock", *this}
  , x509_store_unlock{"X509_STORE_unlock", *this}
  , x509_store_free{"X509_STORE_free", *this}
  , x509_store_add_cert{"X509_STORE_add_cert", *this}
  , x509_store_add_crl{"X509_STORE_add_crl", *this}
  , x509_store_load_locations{"X509_STORE_load_locations", *this}
  , x509_crl_new{"X509_crl_new", *this}
  , x509_crl_free{"X509_crl_free", *this}
  , x509_new{"X509_new", *this}
  , x509_get_pubkey{"X509_get_pubkey", *this}
  , x509_get0_pubkey{"X509_get0_pubkey", *this}
  , x509_get0_serial_number{"X509_get0_serialNumber", *this}
  , x509_get_issuer_name{"X509_get_issuer_name", *this}
  , x509_get_subject_name{"X509_get_subject_name", *this}
  , x509_get_ext_count{"X509_get_ext_count", *this}
  , x509_free{"X509_free", *this}
  , x509_name_entry_count{"X509_NAME_entry_count", *this}
  , x509_name_get_entry{"X509_NAME_get_entry", *this}
  , x509_name_entry_get_object{"X509_NAME_ENTRY_get_object", *this}
  , x509_name_entry_get_data{"X509_NAME_ENTRY_get_data", *this}
  , pem_read_bio_private_key{"PEM_read_bio_PrivateKey", *this}
  , pem_read_bio_pubkey{"PEM_read_bio_PUBKEY", *this}
  , pem_read_bio_x509_crl{"PEM_read_bio_X509_CRL", *this}
  , pem_read_bio_x509{"PEM_read_bio_X509", *this} {}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
