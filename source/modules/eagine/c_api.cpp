/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
module;
#if __has_include(<openssl/conf.h>) && __has_include(<openssl/evp.h>)
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#define EAGINE_HAS_SSL 1
#else
#define EAGINE_HAS_SSL 0
#endif

#ifndef EAGINE_SSL_STATIC_FUNC
#if EAGINE_HAS_SSL
#define EAGINE_SSL_STATIC_FUNC(NAME) &::NAME
#else
#define EAGINE_SSL_STATIC_FUNC(NAME) nullptr
#endif
#endif

export module eagine.sslplus:c_api;

import eagine.core.types;
import eagine.core.c_api;
import :config;
import :api_traits;
import :result;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export template <typename ApiTraits>
struct basic_ssl_c_api {
private:
    ApiTraits& _traits;

public:
    using this_api = basic_ssl_c_api;
    using api_traits = ApiTraits;

    static constexpr bool has_api = ssl_types::has_api;
    using ui_method_type = ssl_types::ui_method_type;
    using engine_type = ssl_types::engine_type;
    using asn1_object_type = ssl_types::asn1_object_type;
    using asn1_string_type = ssl_types::asn1_string_type;
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
    using x509_name_type = ssl_types::x509_name_type;
    using x509_name_entry_type = ssl_types::x509_name_entry_type;
    using x509_store_ctx_type = ssl_types::x509_store_ctx_type;
    using x509_store_type = ssl_types::x509_store_type;
    using x509_crl_type = ssl_types::x509_crl_type;
    using x509_type = ssl_types::x509_type;
    using x509_stack_type = ssl_types::x509_stack_type;

    using passwd_callback_type = int(char*, int, int, void*);

    using x509_store_ctx_verify_callback_type = int(int, x509_store_ctx_type*);

    template <typename Result, typename... U>
    constexpr auto check_result(Result res, U&&...) const noexcept {
        res.error_code(this->err_get_error());
        return res;
    }

    template <typename Result, c_api::result_validity Validity>
    static constexpr auto collapse(
      c_api::result<Result, ssl_result_info, Validity>&& r) noexcept {
        return r.collapsed(
          [](int value) { return value == 1; },
          [](auto& info) { info.set_unknown_error(); });
    }

    template <
      typename Signature,
      c_api::function_ptr<api_traits, nothing_t, Signature> Function>
    using ssl_api_function = c_api::opt_function<
      api_traits,
      nothing_t,
      Signature,
      Function,
      has_api,
      bool(Function)>;

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

    // asn1
    ssl_api_function<
      int(const asn1_string_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_STRING_length)>
      asn1_string_length;

    ssl_api_function<
      const unsigned char*(const asn1_string_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_STRING_get0_data)>
      asn1_string_get0_data;

    ssl_api_function<
      int(std::int64_t*, const asn1_integer_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_INTEGER_get_int64)>
      asn1_integer_get_int64;

    ssl_api_function<
      int(std::uint64_t*, const asn1_integer_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_INTEGER_get_uint64)>
      asn1_integer_get_uint64;

    // obj
    ssl_api_function<
      int(char*, int, const asn1_object_type*, int),
      EAGINE_SSL_STATIC_FUNC(OBJ_obj2txt)>
      obj_obj2txt;

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

    ssl_api_function<
      x509_name_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_issuer_name)>
      x509_get_issuer_name;

    ssl_api_function<
      x509_name_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_subject_name)>
      x509_get_subject_name;

    ssl_api_function<
      int(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_ext_count)>
      x509_get_ext_count;

    ssl_api_function<void(x509_type*), EAGINE_SSL_STATIC_FUNC(X509_free)>
      x509_free;

    // x509 name (entry)
    ssl_api_function<
      int(const x509_name_type*),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_entry_count)>
      x509_name_entry_count;

    ssl_api_function<
      x509_name_entry_type*(const x509_name_type*, int),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_get_entry)>
      x509_name_get_entry;

    ssl_api_function<
      asn1_object_type*(const x509_name_entry_type*),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_ENTRY_get_object)>
      x509_name_entry_get_object;

    ssl_api_function<
      asn1_string_type*(const x509_name_entry_type*),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_ENTRY_get_data)>
      x509_name_entry_get_data;

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

    basic_ssl_c_api(api_traits& traits)
      : _traits{traits}
      , err_get_error{"ERR_get_error", *this}
      , err_peek_error{"ERR_peek_error", *this}
      , err_error_string_n{"ERR_error_string_n", *this}
      , ui_null{"UI_null", *this}
      , ui_openssl{"UI_OpenSSL", *this}
      , ui_get_default_method{"UI_get_default_method", *this}
      , engine_load_builtin_engines{"ENGINE_load_builtin_engines", *this}
      , engine_get_first{"ENGINE_get_first", *this}
      , engine_get_last{"ENGINE_get_last", *this}
      , engine_get_next{"ENGINE_get_next", *this}
      , engine_get_prev{"ENGINE_get_prev", *this}
      , engine_new{"ENGINE_new", *this}
      , engine_by_id{"ENGINE_by_id", *this}
      , engine_up_ref{"ENGINE_up_ref", *this}
      , engine_free{"ENGINE_free", *this}
      , engine_init{"ENGINE_init", *this}
      , engine_finish{"ENGINE_finish", *this}
      , engine_get_id{"ENGINE_get_id", *this}
      , engine_get_name{"ENGINE_get_name", *this}
      , engine_set_default_rsa{"ENGINE_set_default_RSA", *this}
      , engine_set_default_dsa{"ENGINE_set_default_DSA", *this}
      , engine_set_default_dh{"ENGINE_set_default_DH", *this}
      , engine_set_default_rand{"ENGINE_set_default_RAND", *this}
      , engine_set_default_ciphers{"ENGINE_set_default_CIPHERS", *this}
      , engine_set_default_digests{"ENGINE_set_default_DIGESTS", *this}
      , engine_load_private_key{"ENGINE_load_private_key", *this}
      , engine_load_public_key{"ENGINE_load_public_key", *this}
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

    auto traits() noexcept -> api_traits& {
        return _traits;
    }
};
//------------------------------------------------------------------------------
using ssl_c_api = basic_ssl_c_api<ssl_api_traits>;
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
