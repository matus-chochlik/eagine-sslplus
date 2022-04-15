/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_API_HPP
#define EAGINE_SSLPLUS_API_API_HPP

#include "c_api.hpp"
#include "object_handle.hpp"
#include "object_stack.hpp"
#include <eagine/c_api/adapted_function.hpp>
#include <eagine/callable_ref.hpp>
#include <eagine/memory/split_block.hpp>
#include <eagine/scope_exit.hpp>
#include <eagine/string_list.hpp>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
class password_callback {
public:
    constexpr password_callback() noexcept = default;

    constexpr password_callback(
      callable_ref<bool(const string_span, const bool) noexcept>
        callback) noexcept
      : _callback{std::move(callback)} {}

    constexpr auto native_func() noexcept -> auto* {
        return _callback ? &_impl : nullptr;
    }

    constexpr auto native_data() noexcept -> auto* {
        return _callback ? static_cast<void*>(this) : nullptr;
    }

private:
    static auto _impl(
      char* dst,
      const int len,
      const int writing,
      void* ptr) noexcept -> int {
        if(auto* self = static_cast<password_callback*>(ptr)) {
            return self->_callback(
                     string_span(dst, span_size_t(len)), writing != 0)
                     ? 1
                     : 0;
        }
        return 0;
    }

    callable_ref<bool(const string_span, const bool) noexcept> _callback{};
};
} // namespace eagine::sslplus
namespace eagine::c_api {

template <std::size_t CI, std::size_t CppI, typename... CT, typename... CppT>
struct make_args_map<
  CI,
  CppI,
  mp_list<int (*)(char*, int, int, void*), void*, CT...>,
  mp_list<sslplus::password_callback, CppT...>>
  : make_args_map<CI + 2, CppI + 1, mp_list<CT...>, mp_list<CppT...>> {
    using make_args_map<CI + 2, CppI + 1, mp_list<CT...>, mp_list<CppT...>>::
    operator();

    template <typename... P>
    constexpr auto operator()(size_constant<CI> i, P&&... p) const noexcept {
        return reorder_arg_map<CI, CppI>{}(i, std::forward<P>(p)...)
          .native_func();
    }

    template <typename... P>
    constexpr auto operator()(size_constant<CI + 1> i, P&&... p) const noexcept {
        return reorder_arg_map<CI + 1, CppI>{}(i, std::forward<P>(p)...)
          .native_data();
    }
};
} // namespace eagine::c_api
//------------------------------------------------------------------------------
namespace eagine::sslplus {
using c_api::adapted_function;

template <typename ApiTraits>
class basic_ssl_operations : public basic_ssl_c_api<ApiTraits> {

public:
    using api_traits = ApiTraits;
    using ssl_api = basic_ssl_c_api<ApiTraits>;

    adapted_function<&ssl_api::ui_null, ui_method()> null_ui{*this};
    adapted_function<&ssl_api::ui_openssl, ui_method()> openssl_ui{*this};

    adapted_function<&ssl_api::engine_load_builtin_engines> load_builtin_engines{
      *this};

    adapted_function<&ssl_api::engine_get_first, owned_engine()>
      get_first_engine{*this};

    adapted_function<&ssl_api::engine_get_last, owned_engine()> get_last_engine{
      *this};

    adapted_function<&ssl_api::engine_get_next, owned_engine(owned_engine&)>
      get_next_engine{*this};

    adapted_function<&ssl_api::engine_get_prev, owned_engine(owned_engine&)>
      get_prev_engine{*this};

    adapted_function<&ssl_api::engine_new, owned_engine()> new_engine{*this};

    adapted_function<&ssl_api::engine_by_id, owned_engine(string_view)>
      open_engine{*this};

    adapted_function<
      &ssl_api::engine_up_ref,
      owned_engine(engine),
      c_api::replaced_with_map<1>>
      copy_engine{*this};

    adapted_function<&ssl_api::engine_free, c_api::collapsed<int>(owned_engine)>
      delete_engine{*this};

    adapted_function<&ssl_api::engine_init, c_api::collapsed<int>(engine)>
      init_engine{*this};

    adapted_function<&ssl_api::engine_finish, c_api::collapsed<int>(engine)>
      finish_engine{*this};

    adapted_function<&ssl_api::engine_get_id, string_view(engine)> get_engine_id{
      *this};

    adapted_function<&ssl_api::engine_get_name, string_view(engine)>
      get_engine_name{*this};

    adapted_function<
      &ssl_api::engine_set_default_rsa,
      c_api::collapsed<int>(engine)>
      set_default_rsa{*this};

    adapted_function<
      &ssl_api::engine_set_default_dsa,
      c_api::collapsed<int>(engine)>
      set_default_dsa{*this};

    adapted_function<
      &ssl_api::engine_set_default_dh,
      c_api::collapsed<int>(engine)>
      set_default_dh{*this};

    adapted_function<
      &ssl_api::engine_set_default_rand,
      c_api::collapsed<int>(engine)>
      set_default_rand{*this};

    adapted_function<
      &ssl_api::engine_set_default_ciphers,
      c_api::collapsed<int>(engine)>
      set_default_ciphers{*this};

    adapted_function<
      &ssl_api::engine_set_default_digests,
      c_api::collapsed<int>(engine)>
      set_default_digests{*this};

    adapted_function<
      &ssl_api::engine_load_private_key,
      owned_pkey(engine, string_view, ui_method)>
      load_engine_private_key{*this};

    adapted_function<
      &ssl_api::engine_load_public_key,
      owned_pkey(engine, string_view)>
      load_engine_public_key{*this};

    // ASN1
    // string
    adapted_function<&ssl_api::asn1_string_length, span_size_t(asn1_string)>
      get_string_length{*this};

    adapted_function<
      &ssl_api::asn1_string_get0_data,
      const unsigned char*(asn1_string)>
      get_string_data{*this};

    auto get_string_block(asn1_string as) const noexcept
      -> memory::const_block {
        const auto data{get_string_data(as)};
        const auto size{get_string_length(as)};
        if(data && size) {
            return {extract(data), extract(size)};
        }
        return {};
    }

    auto get_string_view(asn1_string as) const noexcept {
        return as_chars(get_string_block(as));
    }

    adapted_function<&ssl_api::asn1_integer_get_int64, std::int64_t(asn1_integer)>
      get_int64{*this};

    adapted_function<
      &ssl_api::asn1_integer_get_uint64,
      std::uint64_t(asn1_integer)>
      get_uint64{*this};

    adapted_function<
      &ssl_api::obj_obj2txt,
      c_api::head_transformed<int, 1>(string_span, asn1_object, bool)>
      object_to_text{*this};

    adapted_function<&ssl_api::bio_new, owned_basic_io(basic_io_method)>
      new_basic_io{*this};

    adapted_function<
      &ssl_api::bio_new_mem_buf,
      owned_basic_io(memory::const_block)>
      new_block_basic_io{*this};

    adapted_function<&ssl_api::bio_free, c_api::collapsed<int>(owned_basic_io)>
      delete_basic_io{*this};

    adapted_function<
      &ssl_api::bio_free_all,
      c_api::collapsed<int>(owned_basic_io)>
      delete_all_basic_ios{*this};

    adapted_function<&ssl_api::rand_bytes, c_api::collapsed<int>(memory::block)>
      random_bytes{*this};

    adapted_function<&ssl_api::evp_pkey_up_ref, owned_pkey(pkey)> copy_pkey{
      *this};

    adapted_function<&ssl_api::evp_pkey_free, void(owned_pkey)> delete_pkey{
      *this};

    adapted_function<&ssl_api::evp_aes_128_ctr, cipher_type()>
      cipher_aes_128_ctr{*this};

    adapted_function<&ssl_api::evp_aes_128_ccm, cipher_type()>
      cipher_aes_128_ccm{*this};

    adapted_function<&ssl_api::evp_aes_128_gcm, cipher_type()>
      cipher_aes_128_gcm{*this};

    adapted_function<&ssl_api::evp_aes_128_xts, cipher_type()>
      cipher_aes_128_xts{*this};

    adapted_function<&ssl_api::evp_aes_192_ecb, cipher_type()>
      cipher_aes_192_ecb{*this};

    adapted_function<&ssl_api::evp_aes_192_cbc, cipher_type()>
      cipher_aes_192_cbc{*this};

    adapted_function<&ssl_api::evp_cipher_ctx_new, owned_cipher()> new_cipher{
      *this};

    adapted_function<&ssl_api::evp_cipher_ctx_free, void(owned_cipher)>
      delete_cipher{*this};

    adapted_function<
      &ssl_api::evp_cipher_ctx_reset,
      c_api::collapsed<int>(cipher)>
      cipher_reset{*this};

    adapted_function<
      &ssl_api::evp_cipher_init,
      c_api::collapsed<
        int>(cipher, cipher_type, memory::const_block, memory::const_block, bool)>
      cipher_init{*this};

    adapted_function<
      &ssl_api::evp_cipher_init_ex,
      c_api::collapsed<int>(
        cipher,
        cipher_type,
        engine,
        memory::const_block,
        memory::const_block,
        bool)>
      cipher_init_ex{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_cipher_update,
        memory::
          split_block(cipher, memory::const_block, int&, memory::const_block)>,
      adapted_function<
        &ssl_api::evp_cipher_update,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped,
          memory::const_block)>>
      cipher_update{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_cipher_final,
        memory::split_block(cipher, memory::const_block, int&)>,
      adapted_function<
        &ssl_api::evp_cipher_final,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      cipher_final{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_cipher_final_ex,
        memory::split_block(cipher, memory::const_block, int&)>,
      adapted_function<
        &ssl_api::evp_cipher_final_ex,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      cipher_final_ex{*this};

    adapted_function<
      &ssl_api::evp_encrypt_init,
      c_api::collapsed<
        int>(cipher, cipher_type, memory::const_block, memory::const_block, bool)>
      encrypt_init{*this};

    adapted_function<
      &ssl_api::evp_encrypt_init_ex,
      c_api::collapsed<int>(
        cipher,
        cipher_type,
        engine,
        memory::const_block,
        memory::const_block,
        bool)>
      encrypt_init_ex{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_encrypt_update,
        memory::
          split_block(cipher, memory::const_block, int&, memory::const_block)>,
      adapted_function<
        &ssl_api::evp_encrypt_update,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped,
          memory::const_block)>>
      encrypt_update{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_encrypt_final,
        memory::split_block(cipher, memory::const_block, int&)>,
      adapted_function<
        &ssl_api::evp_encrypt_final,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      encrypt_final{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_encrypt_final_ex,
        memory::split_block(cipher, memory::const_block, int&)>,
      adapted_function<
        &ssl_api::evp_encrypt_final_ex,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      encrypt_final_ex{*this};

    adapted_function<
      &ssl_api::evp_decrypt_init,
      c_api::collapsed<
        int>(cipher, cipher_type, memory::const_block, memory::const_block, bool)>
      decrypt_init{*this};

    adapted_function<
      &ssl_api::evp_decrypt_init_ex,
      c_api::collapsed<int>(
        cipher,
        cipher_type,
        engine,
        memory::const_block,
        memory::const_block,
        bool)>
      decrypt_init_ex{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_decrypt_update,
        memory::
          split_block(cipher, memory::const_block, int&, memory::const_block)>,
      adapted_function<
        &ssl_api::evp_decrypt_update,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped,
          memory::const_block)>>
      decrypt_update{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_decrypt_final,
        memory::split_block(cipher, memory::const_block, int&)>,
      adapted_function<
        &ssl_api::evp_decrypt_final,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      decrypt_final{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::evp_decrypt_final_ex,
        memory::split_block(cipher, memory::const_block, int&)>,
      adapted_function<
        &ssl_api::evp_decrypt_final_ex,
        c_api::split_transformed<int, 2, 3>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      decrypt_final_ex{*this};

    // message_digest
    adapted_function<&ssl_api::evp_md_null, message_digest_type()>
      message_digest_noop{*this};

    adapted_function<&ssl_api::evp_md5, message_digest_type()>
      message_digest_md5{*this};

    adapted_function<&ssl_api::evp_sha1, message_digest_type()>
      message_digest_sha1{*this};

    adapted_function<&ssl_api::evp_sha224, message_digest_type()>
      message_digest_sha224{*this};

    adapted_function<&ssl_api::evp_sha256, message_digest_type()>
      message_digest_sha256{*this};

    adapted_function<&ssl_api::evp_sha384, message_digest_type()>
      message_digest_sha384{*this};

    adapted_function<&ssl_api::evp_sha512, message_digest_type()>
      message_digest_sha512{*this};

    adapted_function<&ssl_api::evp_md_size, span_size_t(message_digest_type)>
      message_digest_size{*this};

    adapted_function<&ssl_api::evp_md_ctx_new, owned_message_digest()>
      new_message_digest{*this};

    adapted_function<&ssl_api::evp_md_ctx_free, void(owned_message_digest)>
      delete_message_digest{*this};

    adapted_function<
      &ssl_api::evp_md_ctx_reset,
      c_api::collapsed<int>(message_digest)>
      message_digest_reset{*this};

    adapted_function<
      &ssl_api::evp_digest_init,
      c_api::collapsed<int>(message_digest, message_digest_type)>
      message_digest_init{*this};

    adapted_function<
      &ssl_api::evp_digest_init_ex,
      c_api::collapsed<int>(message_digest, message_digest_type, engine)>
      message_digest_init_ex{*this};

    adapted_function<
      &ssl_api::evp_digest_update,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_update{*this};

    adapted_function<
      &ssl_api::evp_digest_final,
      c_api::head_transformed<unsigned, 2, 3>(
        message_digest,
        memory::block,
        c_api::skipped)>
      message_digest_final{*this};

    adapted_function<
      &ssl_api::evp_digest_final_ex,
      c_api::head_transformed<unsigned, 2, 3>(message_digest, memory::block)>
      message_digest_final_ex{*this};

    using _message_digest_sign_init_t = adapted_function<
      &ssl_api::evp_digest_sign_init,
      pkey_ctx(message_digest, pkey_ctx&, message_digest_type, engine, pkey)>;

    struct : _message_digest_sign_init_t {
        using base = _message_digest_sign_init_t;
        using base::base;

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          engine eng,
          pkey pky) const noexcept {
            pkey_ctx pkcx{};
            return base::operator()(mdc, pkcx, mdt, eng, pky)
              .replaced_with(pkcx);
        }

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          pkey pky) const noexcept {
            pkey_ctx pkcx{};
            return base::operator()(mdc, pkcx, mdt, {}, pky).replaced_with(pkcx);
        }
    } message_digest_sign_init{*this};

    adapted_function<
      &ssl_api::evp_digest_sign_update,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_sign_update{*this};

    using _message_digest_sign_final_t = c_api::combined<
      adapted_function<
        &ssl_api::evp_digest_sign_final,
        c_api::collapsed<int>(message_digest, memory::block, size_t&)>,
      adapted_function<
        &ssl_api::evp_digest_sign_final,
        c_api::head_transformed<size_t, 2, 3>(message_digest, memory::block)>>;

    struct : _message_digest_sign_final_t {
        using base = _message_digest_sign_final_t;
        using base::base;

        constexpr auto required_size(message_digest mdc) const noexcept {
            size_t size{0};
            return base::operator()(mdc, {}, size)
              .replaced_with(span_size(size));
        }
    } message_digest_sign_final{*this};

    using _message_digest_verify_init_t = adapted_function<
      &ssl_api::evp_digest_verify_init,
      c_api::collapsed<
        int>(message_digest, pkey_ctx&, message_digest_type, engine, pkey)>;

    struct : _message_digest_verify_init_t {
        using base = _message_digest_verify_init_t;
        using base::base;
        using base::operator();

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          pkey pky) const noexcept {
            pkey_ctx pkc{};
            return base::operator()(mdc, pkc, mdt, {}, pky);
        }

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          engine eng,
          pkey pky) const noexcept {
            pkey_ctx pkc{};
            return base::operator()(mdc, pkc, mdt, eng, pky);
        }
    } message_digest_verify_init{*this};

    adapted_function<
      &ssl_api::evp_digest_verify_update,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_verify_update{*this};

    adapted_function<
      &ssl_api::evp_digest_verify_final,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_verify_final{*this};

    adapted_function<&ssl_api::x509_store_ctx_new, owned_x509_store_ctx()>
      new_x509_store_ctx{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::x509_store_ctx_init,
        c_api::collapsed<
          int>(x509_store_ctx, x509_store, x509, const object_stack<x509>&)>,
      adapted_function<
        &ssl_api::x509_store_ctx_init,
        c_api::collapsed<
          int>(x509_store_ctx, x509_store, x509, c_api::substituted<nullptr>)>>
      init_x509_store_ctx{*this};

    adapted_function<
      &ssl_api::x509_store_ctx_set0_trusted_stack,
      c_api::collapsed<int>(x509_store_ctx, const object_stack<x509>&)>
      set_x509_store_trusted_stack{*this};

    adapted_function<
      &ssl_api::x509_store_ctx_set0_verified_chain,
      c_api::collapsed<int>(x509_store_ctx, const object_stack<x509>&)>
      set_x509_store_verified_chain{*this};

    adapted_function<
      &ssl_api::x509_store_ctx_set0_untrusted,
      c_api::collapsed<int>(x509_store_ctx, const object_stack<x509>&)>
      set_x509_store_untrusted{*this};

    adapted_function<
      &ssl_api::x509_store_ctx_cleanup,
      c_api::collapsed<int>(x509_store_ctx)>
      cleanup_x509_store_ctx{*this};

    adapted_function<&ssl_api::x509_store_ctx_free, void(owned_x509_store_ctx)>
      delete_x509_store_ctx{*this};

    adapted_function<
      &ssl_api::x509_verify_cert,
      c_api::collapsed<int>(x509_store_ctx)>
      x509_verify_certificate{*this};

    adapted_function<&ssl_api::x509_store_new, owned_x509_store()>
      new_x509_store{*this};

    adapted_function<
      &ssl_api::x509_store_up_ref,
      owned_x509_store(x509_store),
      c_api::replaced_with_map<1>>
      copy_x509_store{*this};

    adapted_function<&ssl_api::x509_store_free, void(owned_x509_store)>
      delete_x509_store{*this};

    adapted_function<
      &ssl_api::x509_store_add_cert,
      c_api::collapsed<int>(x509_store, x509)>
      add_cert_into_x509_store{*this};

    adapted_function<
      &ssl_api::x509_store_add_crl,
      c_api::collapsed<int>(x509_store, x509_crl)>
      add_crl_into_x509_store{*this};

    adapted_function<
      &ssl_api::x509_store_load_locations,
      c_api::collapsed<int>(x509_store, string_view)>
      load_into_x509_store{*this};

    adapted_function<&ssl_api::x509_crl_new, owned_x509_crl()> new_x509_crl{
      *this};

    adapted_function<&ssl_api::x509_crl_free, void(owned_x509_crl)>
      delete_x509_crl{*this};

    adapted_function<&ssl_api::x509_new, owned_x509()> new_x509{*this};

    adapted_function<&ssl_api::x509_get_pubkey, owned_pkey(x509)>
      get_x509_pubkey{*this};

    adapted_function<&ssl_api::x509_get0_serial_number, asn1_integer(x509)>
      get_x509_serial_number{*this};

    adapted_function<&ssl_api::x509_get_issuer_name, x509_name(x509)>
      get_x509_issuer_name{*this};

    adapted_function<&ssl_api::x509_get_subject_name, x509_name(x509)>
      get_x509_subject_name{*this};

    adapted_function<&ssl_api::x509_free, void(owned_x509)> delete_x509{*this};

    adapted_function<&ssl_api::x509_name_entry_count, span_size_t(x509_name)>
      get_name_entry_count{*this};

    adapted_function<
      &ssl_api::x509_name_get_entry,
      x509_name_entry(x509_name, span_size_t)>
      get_name_entry{*this};

    adapted_function<
      &ssl_api::x509_name_entry_get_object,
      asn1_object(x509_name_entry)>
      get_name_entry_object{*this};

    adapted_function<
      &ssl_api::x509_name_entry_get_data,
      asn1_string(x509_name_entry)>
      get_name_entry_data{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::pem_read_bio_private_key,
        owned_pkey(basic_io, pkey&, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_private_key,
        owned_pkey(basic_io, c_api::substituted<nullptr>, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_private_key,
        owned_pkey(
          basic_io,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>)>>
      read_bio_private_key{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::pem_read_bio_pubkey,
        owned_pkey(basic_io, pkey&, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_pubkey,
        owned_pkey(basic_io, c_api::substituted<nullptr>, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_pubkey,
        owned_pkey(
          basic_io,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>)>>
      read_bio_public_key{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::pem_read_bio_x509_crl,
        owned_x509_crl(basic_io, x509_crl&, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_x509_crl,
        owned_x509_crl(basic_io, c_api::substituted<nullptr>, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_x509_crl,
        owned_x509_crl(
          basic_io,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>)>>
      read_bio_x509_crl{*this};

    c_api::combined<
      adapted_function<
        &ssl_api::pem_read_bio_x509,
        owned_x509(basic_io, x509&, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_x509,
        owned_x509(basic_io, c_api::substituted<nullptr>, password_callback)>,
      adapted_function<
        &ssl_api::pem_read_bio_x509,
        owned_x509(
          basic_io,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>,
          c_api::substituted<nullptr>)>>
      read_bio_x509{*this};

    basic_ssl_operations(api_traits& traits)
      : ssl_api{traits} {}
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif // EAGINE_SSLPLUS_API_API_HPP
