/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
export module eagine.sslplus:object_handle;
import eagine.core.identifier;
import eagine.core.c_api;
import :config;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
#define EAGINE_SSLPLUS_TAG_TYPE(NAME) static_message_id<"ssl", #NAME>
export using ui_method_tag = EAGINE_SSLPLUS_TAG_TYPE(UIMethod);
export using dispatch_tag = EAGINE_SSLPLUS_TAG_TYPE(Dispatch);
export using core_handle_tag = EAGINE_SSLPLUS_TAG_TYPE(CoreHandle);
export using lib_ctx_tag = EAGINE_SSLPLUS_TAG_TYPE(LibCtx);
export using provider_tag = EAGINE_SSLPLUS_TAG_TYPE(Provider);
export using engine_tag = EAGINE_SSLPLUS_TAG_TYPE(Engine);
export using asn1_object_tag = EAGINE_SSLPLUS_TAG_TYPE(ASN1Object);
export using asn1_string_tag = EAGINE_SSLPLUS_TAG_TYPE(ASN1String);
export using asn1_integer_tag = EAGINE_SSLPLUS_TAG_TYPE(ASN1Integr);
export using basic_io_tag = EAGINE_SSLPLUS_TAG_TYPE(BIO);
export using basic_io_method_tag = EAGINE_SSLPLUS_TAG_TYPE(BIOMethod);
export using cipher_type_tag = EAGINE_SSLPLUS_TAG_TYPE(CipherType);
export using cipher_tag = EAGINE_SSLPLUS_TAG_TYPE(Cipher);
export using message_digest_type_tag = EAGINE_SSLPLUS_TAG_TYPE(MsgDgstTyp);
export using message_digest_tag = EAGINE_SSLPLUS_TAG_TYPE(MsgDigest);
export using pkey_tag = EAGINE_SSLPLUS_TAG_TYPE(PKey);
export using pkey_ctx_tag = EAGINE_SSLPLUS_TAG_TYPE(PKeyCtx);
export using x509_lookup_method_tag = EAGINE_SSLPLUS_TAG_TYPE(X509LkpMtd);
export using x509_lookup_tag = EAGINE_SSLPLUS_TAG_TYPE(X509Lookup);
export using x509_name_tag = EAGINE_SSLPLUS_TAG_TYPE(X509Name);
export using x509_name_entry_tag = EAGINE_SSLPLUS_TAG_TYPE(X509NamEnt);
export using x509_store_ctx_tag = EAGINE_SSLPLUS_TAG_TYPE(X509StrCtx);
export using x509_store_tag = EAGINE_SSLPLUS_TAG_TYPE(X509Store);
export using x509_crl_tag = EAGINE_SSLPLUS_TAG_TYPE(X509Crl);
export using x509_tag = EAGINE_SSLPLUS_TAG_TYPE(X509);
#undef EAGINE_SSLPLUS_TAG_TYPE
//------------------------------------------------------------------------------
export using ui_method =
  c_api::basic_handle<ui_method_tag, ssl_types::ui_method_type*, nullptr>;

export using dispatch =
  c_api::basic_handle<dispatch_tag, ssl_types::dispatch_type*, nullptr>;

export using core_handle =
  c_api::basic_handle<core_handle_tag, ssl_types::core_handle_type*, nullptr>;

export using lib_ctx =
  c_api::basic_handle<lib_ctx_tag, ssl_types::lib_ctx_type*, nullptr>;

export using provider =
  c_api::basic_handle<provider_tag, ssl_types::provider_type*, nullptr>;

export using engine =
  c_api::basic_handle<engine_tag, ssl_types::engine_type*, nullptr>;

export using asn1_object = c_api::
  basic_handle<asn1_object_tag, const ssl_types::asn1_object_type*, nullptr>;

export using asn1_string = c_api::
  basic_handle<asn1_string_tag, const ssl_types::asn1_string_type*, nullptr>;

export using asn1_integer = c_api::
  basic_handle<asn1_integer_tag, const ssl_types::asn1_integer_type*, nullptr>;

export using basic_io =
  c_api::basic_handle<basic_io_tag, ssl_types::bio_type*, nullptr>;

export using basic_io_method = c_api::
  basic_handle<basic_io_method_tag, const ssl_types::bio_method_type*, nullptr>;

export using cipher_type = c_api::
  basic_handle<cipher_type_tag, const ssl_types::evp_cipher_type*, nullptr>;

export using cipher =
  c_api::basic_handle<cipher_tag, ssl_types::evp_cipher_ctx_type*, nullptr>;

export using message_digest_type = c_api::
  basic_handle<message_digest_type_tag, const ssl_types::evp_md_type*, nullptr>;

export using message_digest =
  c_api::basic_handle<message_digest_tag, ssl_types::evp_md_ctx_type*, nullptr>;

export using pkey =
  c_api::basic_handle<pkey_tag, ssl_types::evp_pkey_type*, nullptr>;

export using pkey_ctx =
  c_api::basic_handle<pkey_ctx_tag, ssl_types::evp_pkey_ctx_type*, nullptr>;

export using x509_lookup_method = c_api::basic_handle<
  x509_lookup_method_tag,
  ssl_types::x509_lookup_method_type*,
  nullptr>;

export using x509_name =
  c_api::basic_handle<x509_name_tag, const ssl_types::x509_name_type*, nullptr>;

export using x509_name_entry = c_api::basic_handle<
  x509_name_entry_tag,
  const ssl_types::x509_name_entry_type*,
  nullptr>;

export using x509_store_ctx = c_api::
  basic_handle<x509_store_ctx_tag, ssl_types::x509_store_ctx_type*, nullptr>;

export using x509_store =
  c_api::basic_handle<x509_store_tag, ssl_types::x509_store_type*, nullptr>;

export using x509_crl =
  c_api::basic_handle<x509_crl_tag, ssl_types::x509_crl_type*, nullptr>;

export using x509 =
  c_api::basic_handle<x509_tag, ssl_types::x509_type*, nullptr>;
//------------------------------------------------------------------------------
export using owned_dispatch =
  c_api::basic_owned_handle<dispatch_tag, ssl_types::dispatch_type*, nullptr>;

export using owned_core_handle = c_api::
  basic_owned_handle<core_handle_tag, ssl_types::core_handle_type*, nullptr>;

export using owned_lib_ctx =
  c_api::basic_owned_handle<lib_ctx_tag, ssl_types::lib_ctx_type*, nullptr>;

export using owned_provider =
  c_api::basic_owned_handle<provider_tag, ssl_types::provider_type*, nullptr>;

export using owned_engine =
  c_api::basic_owned_handle<engine_tag, ssl_types::engine_type*, nullptr>;

export using owned_basic_io =
  c_api::basic_owned_handle<basic_io_tag, ssl_types::bio_type*, nullptr>;

export using owned_cipher =
  c_api::basic_owned_handle<cipher_tag, ssl_types::evp_cipher_ctx_type*, nullptr>;

export using owned_message_digest = c_api::
  basic_owned_handle<message_digest_tag, ssl_types::evp_md_ctx_type*, nullptr>;

export using owned_pkey =
  c_api::basic_owned_handle<pkey_tag, ssl_types::evp_pkey_type*, nullptr>;

export using owned_x509_store_ctx = c_api::basic_owned_handle<
  x509_store_ctx_tag,
  ssl_types::x509_store_ctx_type*,
  nullptr>;

export using owned_x509_store =
  c_api::basic_owned_handle<x509_store_tag, ssl_types::x509_store_type*, nullptr>;

export using owned_x509_crl =
  c_api::basic_owned_handle<x509_crl_tag, ssl_types::x509_crl_type*, nullptr>;

export using owned_x509 =
  c_api::basic_owned_handle<x509_tag, ssl_types::x509_type*, nullptr>;
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

