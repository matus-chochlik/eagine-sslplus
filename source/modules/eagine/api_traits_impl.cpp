/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
module;

#if __has_include(<openssl/conf.h>) && __has_include(<openssl/evp.h>)
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/ui.h>
#define EAGINE_HAS_SSL 1
#else
#define EAGINE_HAS_SSL 0
#endif

module eagine.sslplus;
import eagine.core.memory;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
auto ssl_api_traits ::_link_function(const string_view name) -> _any_fnptr_t {
#if EAGINE_HAS_SSL
#define EAGINE_GET_OPENSSL_FUNC(NAME)                 \
    if(name == #NAME) {                               \
        return reinterpret_cast<_any_fnptr_t>(&NAME); \
    }

    EAGINE_GET_OPENSSL_FUNC(ERR_get_error)
    EAGINE_GET_OPENSSL_FUNC(ERR_get_error)
    EAGINE_GET_OPENSSL_FUNC(ERR_peek_error)
    EAGINE_GET_OPENSSL_FUNC(ERR_error_string_n)
    EAGINE_GET_OPENSSL_FUNC(UI_null)
    EAGINE_GET_OPENSSL_FUNC(UI_OpenSSL)
    EAGINE_GET_OPENSSL_FUNC(UI_get_default_method)
    EAGINE_GET_OPENSSL_FUNC(OSSL_LIB_CTX_new)
    EAGINE_GET_OPENSSL_FUNC(OSSL_LIB_CTX_new_from_dispatch)
    EAGINE_GET_OPENSSL_FUNC(OSSL_LIB_CTX_new_child)
    EAGINE_GET_OPENSSL_FUNC(OSSL_LIB_CTX_load_config)
    EAGINE_GET_OPENSSL_FUNC(OSSL_LIB_CTX_get0_global_default)
    EAGINE_GET_OPENSSL_FUNC(OSSL_LIB_CTX_set0_default)
    EAGINE_GET_OPENSSL_FUNC(OSSL_LIB_CTX_free)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_set_default_search_path)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_load)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_try_load)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_unload)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_available)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_get0_dispatch)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_get0_name)
    EAGINE_GET_OPENSSL_FUNC(OSSL_PROVIDER_self_test)
    EAGINE_GET_OPENSSL_FUNC(ASN1_STRING_length)
    EAGINE_GET_OPENSSL_FUNC(ASN1_STRING_get0_data)
    EAGINE_GET_OPENSSL_FUNC(ASN1_INTEGER_get_int64)
    EAGINE_GET_OPENSSL_FUNC(ASN1_INTEGER_get_uint64)
    EAGINE_GET_OPENSSL_FUNC(OBJ_obj2txt)
    EAGINE_GET_OPENSSL_FUNC(BIO_new)
    EAGINE_GET_OPENSSL_FUNC(BIO_new_mem_buf)
    EAGINE_GET_OPENSSL_FUNC(BIO_up_ref)
    EAGINE_GET_OPENSSL_FUNC(BIO_free)
    EAGINE_GET_OPENSSL_FUNC(BIO_free_all)
    EAGINE_GET_OPENSSL_FUNC(RAND_bytes)
    EAGINE_GET_OPENSSL_FUNC(EVP_PKEY_new)
    EAGINE_GET_OPENSSL_FUNC(EVP_PKEY_up_ref)
    EAGINE_GET_OPENSSL_FUNC(EVP_PKEY_free)
    EAGINE_GET_OPENSSL_FUNC(EVP_aes_128_ctr)
    EAGINE_GET_OPENSSL_FUNC(EVP_aes_128_ccm)
    EAGINE_GET_OPENSSL_FUNC(EVP_aes_128_gcm)
    EAGINE_GET_OPENSSL_FUNC(EVP_aes_128_xts)
    EAGINE_GET_OPENSSL_FUNC(EVP_aes_192_ecb)
    EAGINE_GET_OPENSSL_FUNC(EVP_aes_192_cbc)
    EAGINE_GET_OPENSSL_FUNC(EVP_CIPHER_CTX_new)
    EAGINE_GET_OPENSSL_FUNC(EVP_CIPHER_CTX_reset)
    EAGINE_GET_OPENSSL_FUNC(EVP_CIPHER_CTX_free)
    EAGINE_GET_OPENSSL_FUNC(EVP_CipherInit)
    EAGINE_GET_OPENSSL_FUNC(EVP_CipherInit_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_CipherUpdate)
    EAGINE_GET_OPENSSL_FUNC(EVP_CipherFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_CipherFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_EncryptInit)
    EAGINE_GET_OPENSSL_FUNC(EVP_EncryptInit_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_EncryptUpdate)
    EAGINE_GET_OPENSSL_FUNC(EVP_EncryptFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_EncryptFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_DecryptInit)
    EAGINE_GET_OPENSSL_FUNC(EVP_DecryptInit_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_DecryptUpdate)
    EAGINE_GET_OPENSSL_FUNC(EVP_DecryptFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_DecryptFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_md_null)
    EAGINE_GET_OPENSSL_FUNC(EVP_md5)
    EAGINE_GET_OPENSSL_FUNC(EVP_sha1)
    EAGINE_GET_OPENSSL_FUNC(EVP_sha224)
    EAGINE_GET_OPENSSL_FUNC(EVP_sha256)
    EAGINE_GET_OPENSSL_FUNC(EVP_sha384)
    EAGINE_GET_OPENSSL_FUNC(EVP_sha512)
    EAGINE_GET_OPENSSL_FUNC(EVP_get_digestbyname)
    EAGINE_GET_OPENSSL_FUNC(EVP_MD_size)
    EAGINE_GET_OPENSSL_FUNC(EVP_MD_block_size)
    EAGINE_GET_OPENSSL_FUNC(EVP_MD_CTX_new)
    EAGINE_GET_OPENSSL_FUNC(EVP_MD_CTX_reset)
    EAGINE_GET_OPENSSL_FUNC(EVP_MD_CTX_free)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestInit)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestInit_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestUpdate)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestFinal_ex)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestSignInit)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestUpdate)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestSignFinal)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestVerifyInit)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestUpdate)
    EAGINE_GET_OPENSSL_FUNC(EVP_DigestVerifyFinal)
    EAGINE_GET_OPENSSL_FUNC(X509_LOOKUP_hash_dir)
    EAGINE_GET_OPENSSL_FUNC(X509_LOOKUP_file)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_CTX_new)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_CTX_init)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_CTX_set0_trusted_stack)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_CTX_set0_verified_chain)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_CTX_set0_untrusted)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_CTX_cleanup)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_CTX_free)
    EAGINE_GET_OPENSSL_FUNC(X509_verify_cert)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_new)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_up_ref)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_lock)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_unlock)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_free)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_add_cert)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_add_crl)
    EAGINE_GET_OPENSSL_FUNC(X509_STORE_load_locations)
    EAGINE_GET_OPENSSL_FUNC(X509_CRL_new)
    EAGINE_GET_OPENSSL_FUNC(X509_CRL_free)
    EAGINE_GET_OPENSSL_FUNC(X509_new)
    EAGINE_GET_OPENSSL_FUNC(X509_get_pubkey)
    EAGINE_GET_OPENSSL_FUNC(X509_get0_pubkey)
    EAGINE_GET_OPENSSL_FUNC(X509_get0_serialNumber)
    EAGINE_GET_OPENSSL_FUNC(X509_get_issuer_name)
    EAGINE_GET_OPENSSL_FUNC(X509_get_subject_name)
    EAGINE_GET_OPENSSL_FUNC(X509_get_ext_count)
    EAGINE_GET_OPENSSL_FUNC(X509_free)
    EAGINE_GET_OPENSSL_FUNC(X509_NAME_entry_count)
    EAGINE_GET_OPENSSL_FUNC(X509_NAME_get_entry)
    EAGINE_GET_OPENSSL_FUNC(X509_NAME_ENTRY_get_object)
    EAGINE_GET_OPENSSL_FUNC(X509_NAME_ENTRY_get_data)
    EAGINE_GET_OPENSSL_FUNC(PEM_read_bio_PrivateKey)
    EAGINE_GET_OPENSSL_FUNC(PEM_read_bio_PUBKEY)
    EAGINE_GET_OPENSSL_FUNC(PEM_read_bio_X509_CRL)
    EAGINE_GET_OPENSSL_FUNC(PEM_read_bio_X509)
#undef EAGINE_GET_OPENSSL_FUNC
#endif
    return nullptr;
}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
