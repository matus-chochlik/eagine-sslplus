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

export module eagine.sslplus:config;
import eagine.core.types;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export struct ssl_types {
#if EAGINE_HAS_SSL
    static constexpr bool has_api = true;
    using ui_method_type = ::UI_METHOD;
    using dispatch_type = ::OSSL_DISPATCH;
    using core_handle_type = ::OSSL_CORE_HANDLE;
    using lib_ctx_type = ::OSSL_LIB_CTX;
    using provider_type = ::OSSL_PROVIDER;
    using engine_type = ::ENGINE;
    using asn1_object_type = ::ASN1_OBJECT;
    using asn1_string_type = ::ASN1_STRING;
    using asn1_integer_type = ::ASN1_INTEGER;
    using bio_method_type = ::BIO_METHOD;
    using bio_type = ::BIO;
    using evp_pkey_ctx_type = ::EVP_PKEY_CTX;
    using evp_pkey_type = ::EVP_PKEY;
    using evp_cipher_ctx_type = ::EVP_CIPHER_CTX;
    using evp_cipher_type = ::EVP_CIPHER;
    using evp_md_ctx_type = ::EVP_MD_CTX;
    using evp_md_type = ::EVP_MD;
    using x509_lookup_method_type = ::X509_LOOKUP_METHOD;
    using x509_lookup_type = ::X509_LOOKUP;
    using x509_name_type = ::X509_NAME;
    using x509_name_entry_type = ::X509_NAME_ENTRY;
    using x509_store_ctx_type = ::X509_STORE_CTX;
    using x509_store_type = ::X509_STORE;
    using x509_crl_type = ::X509_CRL;
    using x509_type = ::X509;
    using x509_stack_type = STACK_OF(X509);
#else
    static constexpr bool has_api = false;
    using ui_method_type = nothing_t;
    using dispatch_type = nothing_t;
    using core_handle_type = nothing_t;
    using lib_ctx_type = nothing_t;
    using provider_type = nothing_t;
    using engine_type = nothing_t;
    using asn1_object_type = nothing_t;
    using asn1_string_type = nothing_t;
    using asn1_integer_type = nothing_t;
    using bio_method_type = nothing_t;
    using bio_type = nothing_t;
    using evp_pkey_ctx_type = nothing_t;
    using evp_pkey_type = nothing_t;
    using evp_cipher_ctx_type = nothing_t;
    using evp_cipher_type = nothing_t;
    using evp_md_ctx_type = nothing_t;
    using evp_md_type = nothing_t;
    using x509_lookup_method_type = nothing_t;
    using x509_lookup_type = nothing_t;
    using x509_name_type = nothing_t;
    using x509_name_entry_type = nothing_t;
    using x509_store_ctx_type = nothing_t;
    using x509_store_type = nothing_t;
    using x509_crl_type = nothing_t;
    using x509_type = nothing_t;
    using x509_stack_type = nothing_t;
#endif
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

