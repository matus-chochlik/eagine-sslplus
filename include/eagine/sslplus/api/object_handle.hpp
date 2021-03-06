/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_OBJECT_HANDLE_HPP
#define EAGINE_SSLPLUS_API_OBJECT_HANDLE_HPP

#include "config.hpp"
#include <eagine/c_api/handle.hpp>
#include <eagine/message_id.hpp>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
using ui_method_tag = EAGINE_MSG_TYPE(ssl, UIMethod);
using engine_tag = EAGINE_MSG_TYPE(ssl, Engine);
using asn1_object_tag = EAGINE_MSG_TYPE(ssl, ASN1Object);
using asn1_string_tag = EAGINE_MSG_TYPE(ssl, ASN1String);
using asn1_integer_tag = EAGINE_MSG_TYPE(ssl, ASN1Integr);
using basic_io_tag = EAGINE_MSG_TYPE(ssl, BIO);
using basic_io_method_tag = EAGINE_MSG_TYPE(ssl, BIOMethod);
using cipher_type_tag = EAGINE_MSG_TYPE(ssl, CipherType);
using cipher_tag = EAGINE_MSG_TYPE(ssl, Cipher);
using message_digest_type_tag = EAGINE_MSG_TYPE(ssl, MsgDgstTyp);
using message_digest_tag = EAGINE_MSG_TYPE(ssl, MsgDigest);
using pkey_tag = EAGINE_MSG_TYPE(ssl, PKey);
using pkey_ctx_tag = EAGINE_MSG_TYPE(ssl, PKeyCtx);
using x509_lookup_method_tag = EAGINE_MSG_TYPE(ssl, X509LkpMtd);
using x509_lookup_tag = EAGINE_MSG_TYPE(ssl, X509Lookup);
using x509_name_tag = EAGINE_MSG_TYPE(ssl, X509Name);
using x509_name_entry_tag = EAGINE_MSG_TYPE(ssl, X509NamEnt);
using x509_store_ctx_tag = EAGINE_MSG_TYPE(ssl, X509StrCtx);
using x509_store_tag = EAGINE_MSG_TYPE(ssl, X509Store);
using x509_crl_tag = EAGINE_MSG_TYPE(ssl, X509Crl);
using x509_tag = EAGINE_MSG_TYPE(ssl, X509);
//------------------------------------------------------------------------------
using ui_method =
  c_api::basic_handle<ui_method_tag, ssl_types::ui_method_type*, nullptr>;

using engine =
  c_api::basic_handle<engine_tag, ssl_types::engine_type*, nullptr>;

using asn1_object = c_api::
  basic_handle<asn1_object_tag, const ssl_types::asn1_object_type*, nullptr>;

using asn1_string = c_api::
  basic_handle<asn1_string_tag, const ssl_types::asn1_string_type*, nullptr>;

using asn1_integer = c_api::
  basic_handle<asn1_integer_tag, const ssl_types::asn1_integer_type*, nullptr>;

using basic_io =
  c_api::basic_handle<basic_io_tag, ssl_types::bio_type*, nullptr>;

using basic_io_method = c_api::
  basic_handle<basic_io_method_tag, const ssl_types::bio_method_type*, nullptr>;

using cipher_type = c_api::
  basic_handle<cipher_type_tag, const ssl_types::evp_cipher_type*, nullptr>;

using cipher =
  c_api::basic_handle<cipher_tag, ssl_types::evp_cipher_ctx_type*, nullptr>;

using message_digest_type = c_api::
  basic_handle<message_digest_type_tag, const ssl_types::evp_md_type*, nullptr>;

using message_digest =
  c_api::basic_handle<message_digest_tag, ssl_types::evp_md_ctx_type*, nullptr>;

using pkey = c_api::basic_handle<pkey_tag, ssl_types::evp_pkey_type*, nullptr>;

using pkey_ctx =
  c_api::basic_handle<pkey_ctx_tag, ssl_types::evp_pkey_ctx_type*, nullptr>;

using x509_lookup_method = c_api::basic_handle<
  x509_lookup_method_tag,
  ssl_types::x509_lookup_method_type*,
  nullptr>;

using x509_name =
  c_api::basic_handle<x509_name_tag, const ssl_types::x509_name_type*, nullptr>;

using x509_name_entry = c_api::basic_handle<
  x509_name_entry_tag,
  const ssl_types::x509_name_entry_type*,
  nullptr>;

using x509_store_ctx = c_api::
  basic_handle<x509_store_ctx_tag, ssl_types::x509_store_ctx_type*, nullptr>;

using x509_store =
  c_api::basic_handle<x509_store_tag, ssl_types::x509_store_type*, nullptr>;

using x509_crl =
  c_api::basic_handle<x509_crl_tag, ssl_types::x509_crl_type*, nullptr>;

using x509 = c_api::basic_handle<x509_tag, ssl_types::x509_type*, nullptr>;
//------------------------------------------------------------------------------
using owned_engine =
  c_api::basic_owned_handle<engine_tag, ssl_types::engine_type*, nullptr>;

using owned_basic_io =
  c_api::basic_owned_handle<basic_io_tag, ssl_types::bio_type*, nullptr>;

using owned_cipher =
  c_api::basic_owned_handle<cipher_tag, ssl_types::evp_cipher_ctx_type*, nullptr>;

using owned_message_digest = c_api::
  basic_owned_handle<message_digest_tag, ssl_types::evp_md_ctx_type*, nullptr>;

using owned_pkey =
  c_api::basic_owned_handle<pkey_tag, ssl_types::evp_pkey_type*, nullptr>;

using owned_x509_store_ctx = c_api::basic_owned_handle<
  x509_store_ctx_tag,
  ssl_types::x509_store_ctx_type*,
  nullptr>;

using owned_x509_store =
  c_api::basic_owned_handle<x509_store_tag, ssl_types::x509_store_type*, nullptr>;

using owned_x509_crl =
  c_api::basic_owned_handle<x509_crl_tag, ssl_types::x509_crl_type*, nullptr>;

using owned_x509 =
  c_api::basic_owned_handle<x509_tag, ssl_types::x509_type*, nullptr>;
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif // EAGINE_SSLPLUS_API_OBJECT_HANDLE_HPP
