/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_C_API_HPP
#define EAGINE_SSLPLUS_API_C_API_HPP

#include "api_traits.hpp"
#include "config.hpp"
#include <eagine/nothing.hpp>
#include <eagine/preprocessor.hpp>

#ifndef EAGINE_SSL_STATIC_FUNC
#if EAGINE_HAS_SSL
#define EAGINE_SSL_STATIC_FUNC(NAME) &::NAME
#else
#define EAGINE_SSL_STATIC_FUNC(NAME) nullptr
#endif
#endif

namespace eagine::sslplus {
//------------------------------------------------------------------------------
template <typename ApiTraits>
struct basic_ssl_c_api {

    using this_api = basic_ssl_c_api;
    using api_traits = ApiTraits;

    static constexpr bool has_api = ssl_types::has_api;
    using ui_method_type = ssl_types::ui_method_type;
    using engine_type = ssl_types::engine_type;
    using asn1_integer_type = ssl_types::asn1_integer_type;
    using bio_method_type = ssl_types::bio_method_type;
    using bio_type = ssl_types::bio_type;
    using evp_pkey_ctx_type = ssl_types::evp_pkey_ctx_type;
    using evp_pkey_type = ssl_types::evp_pkey_type;
    using evp_cipher_ctx_type = ssl_types::evp_cipher_ctx_type;
    using evp_cipher_type = ssl_types::evp_cipher_type;
    using evp_md_ctx_type = ssl_types::evp_md_ctx_type;
    using evp_md_type = ssl_types::evp_md_type;
    using x509_lookup_method_type = ssl_types::x509_lookup_method_type;
    using x509_lookup_type = ssl_types::x509_lookup_type;
    using x509_store_ctx_type = ssl_types::x509_store_ctx_type;
    using x509_store_type = ssl_types::x509_store_type;
    using x509_crl_type = ssl_types::x509_crl_type;
    using x509_type = ssl_types::x509_type;
    using x509_stack_type = ssl_types::x509_stack_type;

    using passwd_callback_type = int(char*, int, int, void*);

    using x509_store_ctx_verify_callback_type = int(int, x509_store_ctx_type*);

#ifdef __GNUC__
    EAGINE_DIAG_PUSH()
    EAGINE_DIAG_OFF(address)
#endif
    template <
      typename Signature,
      c_api_function_ptr<api_traits, nothing_t, Signature> Function>
    using ssl_api_function = eagine::opt_c_api_function<
      api_traits,
      nothing_t,
      Signature,
      Function,
      has_api,
      bool(Function)>;
#ifdef __GNUC__
    EAGINE_DIAG_POP()
#endif

    // error
    ssl_api_function<unsigned long(), EAGINE_SSL_STATIC_FUNC(ERR_get_error)>
      err_get_error;

    ssl_api_function<unsigned long(), EAGINE_SSL_STATIC_FUNC(ERR_peek_error)>
      err_peek_error;

    ssl_api_function<
      void(unsigned long, char*, size_t),
      EAGINE_SSL_STATIC_FUNC(ERR_error_string_n)>
      err_error_string_n;

    // ui method
    ssl_api_function<const ui_method_type*(), EAGINE_SSL_STATIC_FUNC(UI_null)>
      ui_null;

    ssl_api_function<ui_method_type*(), EAGINE_SSL_STATIC_FUNC(UI_OpenSSL)>
      ui_openssl;

    ssl_api_function<
      const ui_method_type*(),
      EAGINE_SSL_STATIC_FUNC(UI_get_default_method)>
      ui_get_default_method;

    // engine
    ssl_api_function<void(), EAGINE_SSL_STATIC_FUNC(ENGINE_load_builtin_engines)>
      engine_load_builtin_engines;

    ssl_api_function<engine_type*(), EAGINE_SSL_STATIC_FUNC(ENGINE_get_first)>
      engine_get_first;

    ssl_api_function<engine_type*(), EAGINE_SSL_STATIC_FUNC(ENGINE_get_last)>
      engine_get_last;

    ssl_api_function<
      engine_type*(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_get_next)>
      engine_get_next;

    ssl_api_function<
      engine_type*(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_get_prev)>
      engine_get_prev;

    ssl_api_function<engine_type*(), EAGINE_SSL_STATIC_FUNC(ENGINE_new)>
      engine_new;

    ssl_api_function<
      engine_type*(const char*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_by_id)>
      engine_by_id;

    ssl_api_function<int(engine_type*), EAGINE_SSL_STATIC_FUNC(ENGINE_up_ref)>
      engine_up_ref;

    ssl_api_function<int(engine_type*), EAGINE_SSL_STATIC_FUNC(ENGINE_free)>
      engine_free;

    ssl_api_function<int(engine_type*), EAGINE_SSL_STATIC_FUNC(ENGINE_init)>
      engine_init;

    ssl_api_function<int(engine_type*), EAGINE_SSL_STATIC_FUNC(ENGINE_finish)>
      engine_finish;

    ssl_api_function<
      const char*(const engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_get_id)>
      engine_get_id;

    ssl_api_function<
      const char*(const engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_get_name)>
      engine_get_name;

    ssl_api_function<
      int(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_set_default_RSA)>
      engine_set_default_rsa;

    ssl_api_function<
      int(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_set_default_DSA)>
      engine_set_default_dsa;

    ssl_api_function<
      int(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_set_default_DH)>
      engine_set_default_dh;

    ssl_api_function<
      int(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_set_default_RAND)>
      engine_set_default_rand;

    ssl_api_function<
      int(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_set_default_ciphers)>
      engine_set_default_ciphers;

    ssl_api_function<
      int(engine_type*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_set_default_digests)>
      engine_set_default_digests;

    ssl_api_function<
      evp_pkey_type*(engine_type*, const char*, ui_method_type*, void*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_load_private_key)>
      engine_load_private_key;

    ssl_api_function<
      evp_pkey_type*(engine_type*, const char*, ui_method_type*, void*),
      EAGINE_SSL_STATIC_FUNC(ENGINE_load_public_key)>
      engine_load_public_key;

    // bio
    ssl_api_function<
      bio_type*(const bio_method_type*),
      EAGINE_SSL_STATIC_FUNC(BIO_new)>
      bio_new;

    ssl_api_function<
      bio_type*(const void*, int),
      EAGINE_SSL_STATIC_FUNC(BIO_new_mem_buf)>
      bio_new_mem_buf;

    ssl_api_function<int(bio_type*), EAGINE_SSL_STATIC_FUNC(BIO_up_ref)>
      bio_up_ref;

    ssl_api_function<int(bio_type*), EAGINE_SSL_STATIC_FUNC(BIO_free)> bio_free;

    ssl_api_function<void(bio_type*), EAGINE_SSL_STATIC_FUNC(BIO_free_all)>
      bio_free_all;

    // random
    ssl_api_function<
      int(unsigned char*, int num),
      EAGINE_SSL_STATIC_FUNC(RAND_bytes)>
      rand_bytes;

    // pkey
    ssl_api_function<evp_pkey_type*(), EAGINE_SSL_STATIC_FUNC(EVP_PKEY_new)>
      evp_pkey_new;

    ssl_api_function<int(evp_pkey_type*), EAGINE_SSL_STATIC_FUNC(EVP_PKEY_up_ref)>
      evp_pkey_up_ref;

    ssl_api_function<void(evp_pkey_type*), EAGINE_SSL_STATIC_FUNC(EVP_PKEY_free)>
      evp_pkey_free;

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_ctr)>
      evp_aes_128_ctr;

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_ccm)>
      evp_aes_128_ccm;

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_gcm)>
      evp_aes_128_gcm;

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_xts)>
      evp_aes_128_xts;

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_192_ecb)>
      evp_aes_192_ecb;

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_192_cbc)>
      evp_aes_192_cbc;

    ssl_api_function<
      evp_cipher_ctx_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_CIPHER_CTX_new)>
      evp_cipher_ctx_new;

    ssl_api_function<
      int(evp_cipher_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_CIPHER_CTX_reset)>
      evp_cipher_ctx_reset;

    ssl_api_function<
      void(evp_cipher_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_CIPHER_CTX_free)>
      evp_cipher_ctx_free;

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        const unsigned char*,
        const unsigned char*,
        int),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherInit)>
      evp_cipher_init;

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        engine_type*,
        const unsigned char*,
        const unsigned char*,
        int),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherInit_ex)>
      evp_cipher_init_ex;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*, const unsigned char*, int),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherUpdate)>
      evp_cipher_update;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherFinal_ex)>
      evp_cipher_final;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherFinal_ex)>
      evp_cipher_final_ex;

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptInit)>
      evp_encrypt_init;

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        engine_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptInit_ex)>
      evp_encrypt_init_ex;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*, const unsigned char*, int),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptUpdate)>
      evp_encrypt_update;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptFinal_ex)>
      evp_encrypt_final;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptFinal_ex)>
      evp_encrypt_final_ex;

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptInit)>
      evp_decrypt_init;

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        engine_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptInit_ex)>
      evp_decrypt_init_ex;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*, const unsigned char*, int),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptUpdate)>
      evp_decrypt_update;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptFinal_ex)>
      evp_decrypt_final;

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptFinal_ex)>
      evp_decrypt_final_ex;

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_md_null)>
      evp_md_null;

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_md5)>
      evp_md5;

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha1)>
      evp_sha1;

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha224)>
      evp_sha224;

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha256)>
      evp_sha256;

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha384)>
      evp_sha384;

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha512)>
      evp_sha512;

    ssl_api_function<
      const evp_md_type*(const char*),
      EAGINE_SSL_STATIC_FUNC(EVP_get_digestbyname)>
      evp_get_digest_by_name;

    ssl_api_function<int(const evp_md_type*), EAGINE_SSL_STATIC_FUNC(EVP_MD_size)>
      evp_md_size;

    ssl_api_function<
      int(const evp_md_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_MD_block_size)>
      evp_md_block_size;

    ssl_api_function<evp_md_ctx_type*(), EAGINE_SSL_STATIC_FUNC(EVP_MD_CTX_new)>
      evp_md_ctx_new;

    ssl_api_function<
      int(evp_md_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_MD_CTX_reset)>
      evp_md_ctx_reset;

    ssl_api_function<
      void(evp_md_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_MD_CTX_free)>
      evp_md_ctx_free;

    ssl_api_function<
      int(evp_md_ctx_type*, const evp_md_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestInit)>
      evp_digest_init;

    ssl_api_function<
      int(evp_md_ctx_type*, const evp_md_type*, engine_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestInit_ex)>
      evp_digest_init_ex;

    ssl_api_function<
      int(evp_md_ctx_type*, const void*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestUpdate)>
      evp_digest_update;

    ssl_api_function<
      int(evp_md_ctx_type*, unsigned char*, unsigned int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestFinal_ex)>
      evp_digest_final;

    ssl_api_function<
      int(evp_md_ctx_type*, unsigned char*, unsigned int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestFinal_ex)>
      evp_digest_final_ex;

    ssl_api_function<
      int(
        evp_md_ctx_type*,
        evp_pkey_ctx_type**,
        const evp_md_type*,
        engine_type*,
        evp_pkey_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestSignInit)>
      evp_digest_sign_init;

    ssl_api_function<
      int(evp_md_ctx_type*, const void*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestUpdate)>
      evp_digest_sign_update;

    ssl_api_function<
      int(evp_md_ctx_type*, unsigned char*, size_t*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestSignFinal)>
      evp_digest_sign_final;

    ssl_api_function<
      int(
        evp_md_ctx_type*,
        evp_pkey_ctx_type**,
        const evp_md_type*,
        engine_type*,
        evp_pkey_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestVerifyInit)>
      evp_digest_verify_init;

    ssl_api_function<
      int(evp_md_ctx_type*, const void*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestUpdate)>
      evp_digest_verify_update;

    ssl_api_function<
      int(evp_md_ctx_type*, const unsigned char*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestVerifyFinal)>
      evp_digest_verify_final;

    // x509 lookup
    ssl_api_function<
      x509_lookup_method_type*(),
      EAGINE_SSL_STATIC_FUNC(X509_LOOKUP_hash_dir)>
      x509_lookup_hash_dir;

    ssl_api_function<
      x509_lookup_method_type*(),
      EAGINE_SSL_STATIC_FUNC(X509_LOOKUP_file)>
      x509_lookup_file;

    // x509 store context
    ssl_api_function<
      x509_store_ctx_type*(),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_new)>
      x509_store_ctx_new;

    ssl_api_function<
      int(x509_store_ctx_type*, x509_store_type*, x509_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_init)>
      x509_store_ctx_init;

    ssl_api_function<
      void(x509_store_ctx_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_set0_trusted_stack)>
      x509_store_ctx_set0_trusted_stack;

    ssl_api_function<
      void(x509_store_ctx_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_set0_verified_chain)>
      x509_store_ctx_set0_verified_chain;

    ssl_api_function<
      void(x509_store_ctx_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_set0_untrusted)>
      x509_store_ctx_set0_untrusted;

    ssl_api_function<
      void(x509_store_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_cleanup)>
      x509_store_ctx_cleanup;

    ssl_api_function<
      void(x509_store_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_free)>
      x509_store_ctx_free;

    ssl_api_function<
      int(x509_store_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(X509_verify_cert)>
      x509_verify_cert;

    // x509 store
    ssl_api_function<x509_store_type*(), EAGINE_SSL_STATIC_FUNC(X509_STORE_new)>
      x509_store_new;

    ssl_api_function<
      int(x509_store_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_up_ref)>
      x509_store_up_ref;

    ssl_api_function<
      int(x509_store_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_lock)>
      x509_store_lock;

    ssl_api_function<
      int(x509_store_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_unlock)>
      x509_store_unlock;

    ssl_api_function<
      void(x509_store_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_free)>
      x509_store_free;

    ssl_api_function<
      int(x509_store_type*, x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_add_cert)>
      x509_store_add_cert;

    ssl_api_function<
      int(x509_store_type*, x509_crl_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_add_crl)>
      x509_store_add_crl;

    ssl_api_function<
      int(x509_store_type*, const char*, const char*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_load_locations)>
      x509_store_load_locations;

    // x509_crl
    ssl_api_function<x509_crl_type*(), EAGINE_SSL_STATIC_FUNC(X509_CRL_new)>
      x509_crl_new;

    ssl_api_function<void(x509_crl_type*), EAGINE_SSL_STATIC_FUNC(X509_CRL_free)>
      x509_crl_free;

    // x509
    ssl_api_function<x509_type*(), EAGINE_SSL_STATIC_FUNC(X509_new)> x509_new;

    ssl_api_function<
      evp_pkey_type*(x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_pubkey)>
      x509_get_pubkey;

    ssl_api_function<
      evp_pkey_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get0_pubkey)>
      x509_get0_pubkey;

    ssl_api_function<
      const asn1_integer_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get0_serialNumber)>
      x509_get0_serial_number;

    ssl_api_function<void(x509_type*), EAGINE_SSL_STATIC_FUNC(X509_free)>
      x509_free;

    // pem
    ssl_api_function<
      evp_pkey_type*(bio_type*, evp_pkey_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_PrivateKey)>
      pem_read_bio_private_key;

    ssl_api_function<
      evp_pkey_type*(bio_type*, evp_pkey_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_PUBKEY)>
      pem_read_bio_pubkey;

    ssl_api_function<
      x509_crl_type*(bio_type*, x509_crl_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_X509_CRL)>
      pem_read_bio_x509_crl;

    ssl_api_function<
      x509_type*(bio_type*, x509_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_X509)>
      pem_read_bio_x509;

    basic_ssl_c_api(api_traits& traits);
};
//------------------------------------------------------------------------------
using ssl_c_api = basic_ssl_c_api<ssl_api_traits>;
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif
