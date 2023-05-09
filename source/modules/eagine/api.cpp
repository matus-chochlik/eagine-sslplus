/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
export module eagine.sslplus:api;

import std;
import eagine.core.types;
import eagine.core.memory;
import eagine.core.string;
import eagine.core.utility;
import eagine.core.c_api;
import :config;
import :api_traits;
import :result;
import :object_handle;
import :object_stack;
import :constants;
import :c_api;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export class password_callback {
public:
    constexpr password_callback() noexcept = default;

    constexpr password_callback(
      callable_ref<bool(const memory::string_span, const bool) noexcept>
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
                     memory::string_span(dst, span_size_t(len)), writing != 0)
                     ? 1
                     : 0;
        }
        return 0;
    }

    callable_ref<bool(const memory::string_span, const bool) noexcept>
      _callback{};
};
} // namespace eagine::sslplus
//------------------------------------------------------------------------------
namespace eagine::c_api {

export template <std::size_t CI, std::size_t CppI, typename... CT, typename... CppT>
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
using c_api::plain_adapted_function;
using c_api::simple_adapted_function;

export template <typename ApiTraits>
class basic_ssl_operations : public basic_ssl_c_api<ApiTraits> {

public:
    using api_traits = ApiTraits;
    using ssl_api = basic_ssl_c_api<ApiTraits>;

    simple_adapted_function<&ssl_api::ui_null, ui_method()> null_ui{*this};
    simple_adapted_function<&ssl_api::ui_openssl, ui_method()> openssl_ui{
      *this};

    simple_adapted_function<&ssl_api::lib_ctx_new, owned_lib_ctx()> new_lib_ctx{
      *this};

    simple_adapted_function<
      &ssl_api::lib_ctx_new_from_dispatch,
      owned_lib_ctx(core_handle, dispatch)>
      new_lib_ctx_from_dispatch{*this};

    simple_adapted_function<
      &ssl_api::lib_ctx_new_child,
      owned_lib_ctx(core_handle, dispatch)>
      new_lib_ctx_child{*this};

    simple_adapted_function<
      &ssl_api::lib_ctx_load_config,
      bool(lib_ctx, string_view)>
      load_lib_ctx_config{*this};

    simple_adapted_function<&ssl_api::lib_ctx_get_global_default, lib_ctx()>
      get_default_lib_ctx{*this};

    simple_adapted_function<
      &ssl_api::lib_ctx_get_global_default,
      lib_ctx(lib_ctx)>
      set_default_lib_ctx{*this};

    simple_adapted_function<
      &ssl_api::lib_ctx_free,
      c_api::collapsed<int>(owned_lib_ctx)>
      delete_lib_ctx{*this};

    simple_adapted_function<
      &ssl_api::provider_set_default_search_path,
      void(lib_ctx, string_view)>
      set_default_provider_search_path{*this};

    simple_adapted_function<
      &ssl_api::provider_load,
      provider(lib_ctx, string_view)>
      load_provider{*this};

    simple_adapted_function<
      &ssl_api::provider_try_load,
      provider(lib_ctx, string_view)>
      try_load_provider{*this};

    simple_adapted_function<&ssl_api::provider_unload, void(provider)>
      unload_provider{*this};

    simple_adapted_function<
      &ssl_api::provider_available,
      bool(lib_ctx, string_view)>
      is_provider_available{*this};

    simple_adapted_function<&ssl_api::provider_get_name, string_view(provider)>
      get_provider_name{*this};

    simple_adapted_function<&ssl_api::provider_get_dispatch, dispatch(provider)>
      get_provider_dispatch{*this};

    simple_adapted_function<&ssl_api::provider_get_dispatch, bool(provider)>
      provider_self_test{*this};

    // ASN1
    // string
    simple_adapted_function<
      &ssl_api::asn1_string_length,
      span_size_t(asn1_string)>
      get_string_length{*this};

    simple_adapted_function<
      &ssl_api::asn1_string_get0_data,
      const unsigned char*(asn1_string)>
      get_string_data{*this};

    auto get_string_block(asn1_string as) const noexcept
      -> memory::const_block {
        const auto data{get_string_data(as)};
        const auto size{get_string_length(as)};
        if(data and size) {
            return {extract(data), extract(size)};
        }
        return {};
    }

    auto get_string_view(asn1_string as) const noexcept -> string_view {
        return as_chars(get_string_block(as));
    }

    simple_adapted_function<
      &ssl_api::asn1_integer_get_int64,
      std::int64_t(asn1_integer)>
      get_int64{*this};

    simple_adapted_function<
      &ssl_api::asn1_integer_get_uint64,
      std::uint64_t(asn1_integer)>
      get_uint64{*this};

    simple_adapted_function<
      &ssl_api::obj_obj2txt,
      c_api::head_transformed<int, 0, 1>(memory::string_span, asn1_object, bool)>
      object_to_text{*this};

    auto get_object_text(
      memory::string_span dest,
      asn1_object obj,
      bool no_name) const noexcept -> string_view {
        return this->object_to_text(dest, obj, no_name).or_default();
    }

    simple_adapted_function<&ssl_api::bio_new, owned_basic_io(basic_io_method)>
      new_basic_io{*this};

    simple_adapted_function<
      &ssl_api::bio_new_mem_buf,
      owned_basic_io(memory::const_block)>
      new_block_basic_io{*this};

    simple_adapted_function<
      &ssl_api::bio_free,
      c_api::collapsed<int>(owned_basic_io)>
      delete_basic_io{*this};

    simple_adapted_function<
      &ssl_api::bio_free_all,
      c_api::collapsed<int>(owned_basic_io)>
      delete_all_basic_ios{*this};

    simple_adapted_function<
      &ssl_api::rand_bytes,
      c_api::collapsed<int>(memory::block)>
      random_bytes{*this};

    simple_adapted_function<&ssl_api::evp_pkey_up_ref, owned_pkey(pkey)>
      copy_pkey{*this};

    simple_adapted_function<&ssl_api::evp_pkey_free, void(owned_pkey)>
      delete_pkey{*this};

    simple_adapted_function<&ssl_api::evp_aes_128_ctr, cipher_type()>
      cipher_aes_128_ctr{*this};

    simple_adapted_function<&ssl_api::evp_aes_128_ccm, cipher_type()>
      cipher_aes_128_ccm{*this};

    simple_adapted_function<&ssl_api::evp_aes_128_gcm, cipher_type()>
      cipher_aes_128_gcm{*this};

    simple_adapted_function<&ssl_api::evp_aes_128_xts, cipher_type()>
      cipher_aes_128_xts{*this};

    simple_adapted_function<&ssl_api::evp_aes_192_ecb, cipher_type()>
      cipher_aes_192_ecb{*this};

    simple_adapted_function<&ssl_api::evp_aes_192_cbc, cipher_type()>
      cipher_aes_192_cbc{*this};

    simple_adapted_function<&ssl_api::evp_cipher_ctx_new, owned_cipher()>
      new_cipher{*this};

    simple_adapted_function<&ssl_api::evp_cipher_ctx_free, void(owned_cipher)>
      delete_cipher{*this};

    simple_adapted_function<
      &ssl_api::evp_cipher_ctx_reset,
      c_api::collapsed<int>(cipher)>
      cipher_reset{*this};

    simple_adapted_function<
      &ssl_api::evp_cipher_init,
      c_api::collapsed<
        int>(cipher, cipher_type, memory::const_block, memory::const_block, bool)>
      cipher_init{*this};

    simple_adapted_function<
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
      simple_adapted_function<
        &ssl_api::evp_cipher_update,
        memory::
          split_block(cipher, memory::const_block, int&, memory::const_block)>,
      simple_adapted_function<
        &ssl_api::evp_cipher_update,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped,
          memory::const_block)>>
      cipher_update{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::evp_cipher_final,
        memory::split_block(cipher, memory::const_block, int&)>,
      simple_adapted_function<
        &ssl_api::evp_cipher_final,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      cipher_final{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::evp_cipher_final_ex,
        memory::split_block(cipher, memory::const_block, int&)>,
      simple_adapted_function<
        &ssl_api::evp_cipher_final_ex,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      cipher_final_ex{*this};

    simple_adapted_function<
      &ssl_api::evp_encrypt_init,
      c_api::collapsed<
        int>(cipher, cipher_type, memory::const_block, memory::const_block, bool)>
      encrypt_init{*this};

    simple_adapted_function<
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
      simple_adapted_function<
        &ssl_api::evp_encrypt_update,
        memory::
          split_block(cipher, memory::const_block, int&, memory::const_block)>,
      simple_adapted_function<
        &ssl_api::evp_encrypt_update,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped,
          memory::const_block)>>
      encrypt_update{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::evp_encrypt_final,
        memory::split_block(cipher, memory::const_block, int&)>,
      simple_adapted_function<
        &ssl_api::evp_encrypt_final,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      encrypt_final{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::evp_encrypt_final_ex,
        memory::split_block(cipher, memory::const_block, int&)>,
      simple_adapted_function<
        &ssl_api::evp_encrypt_final_ex,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      encrypt_final_ex{*this};

    simple_adapted_function<
      &ssl_api::evp_decrypt_init,
      c_api::collapsed<
        int>(cipher, cipher_type, memory::const_block, memory::const_block, bool)>
      decrypt_init{*this};

    simple_adapted_function<
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
      simple_adapted_function<
        &ssl_api::evp_decrypt_update,
        memory::
          split_block(cipher, memory::const_block, int&, memory::const_block)>,
      simple_adapted_function<
        &ssl_api::evp_decrypt_update,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped,
          memory::const_block)>>
      decrypt_update{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::evp_decrypt_final,
        memory::split_block(cipher, memory::const_block, int&)>,
      simple_adapted_function<
        &ssl_api::evp_decrypt_final,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      decrypt_final{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::evp_decrypt_final_ex,
        memory::split_block(cipher, memory::const_block, int&)>,
      simple_adapted_function<
        &ssl_api::evp_decrypt_final_ex,
        c_api::split_transformed<int, 3, 2>(
          cipher,
          memory::split_block,
          c_api::skipped)>>
      decrypt_final_ex{*this};

    // message_digest
    simple_adapted_function<&ssl_api::evp_md_null, message_digest_type()>
      message_digest_noop{*this};

    simple_adapted_function<&ssl_api::evp_md5, message_digest_type()>
      message_digest_md5{*this};

    simple_adapted_function<&ssl_api::evp_sha1, message_digest_type()>
      message_digest_sha1{*this};

    simple_adapted_function<&ssl_api::evp_sha224, message_digest_type()>
      message_digest_sha224{*this};

    simple_adapted_function<&ssl_api::evp_sha256, message_digest_type()>
      message_digest_sha256{*this};

    simple_adapted_function<&ssl_api::evp_sha384, message_digest_type()>
      message_digest_sha384{*this};

    simple_adapted_function<&ssl_api::evp_sha512, message_digest_type()>
      message_digest_sha512{*this};

    simple_adapted_function<
      &ssl_api::evp_md_size,
      span_size_t(message_digest_type)>
      message_digest_size{*this};

    simple_adapted_function<&ssl_api::evp_md_ctx_new, owned_message_digest()>
      new_message_digest{*this};

    simple_adapted_function<&ssl_api::evp_md_ctx_free, void(owned_message_digest)>
      delete_message_digest{*this};

    simple_adapted_function<
      &ssl_api::evp_md_ctx_reset,
      c_api::collapsed<int>(message_digest)>
      message_digest_reset{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_init,
      c_api::collapsed<int>(message_digest, message_digest_type)>
      message_digest_init{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_init_ex,
      c_api::collapsed<int>(message_digest, message_digest_type, engine)>
      message_digest_init_ex{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_update,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_update{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_final,
      c_api::head_transformed<unsigned, 3, 2>(
        message_digest,
        memory::block,
        c_api::skipped)>
      message_digest_final{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_final_ex,
      c_api::head_transformed<unsigned, 3, 2>(message_digest, memory::block)>
      message_digest_final_ex{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_sign_init,
      c_api::returned<pkey_ctx>(
        message_digest,
        c_api::returned<pkey_ctx>,
        message_digest_type,
        engine,
        pkey)>
      message_digest_sign_init{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_sign_update,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_sign_update{*this};

    using _message_digest_sign_final_t = c_api::combined<
      simple_adapted_function<
        &ssl_api::evp_digest_sign_final,
        c_api::collapsed<int>(message_digest, memory::block, size_t&)>,
      simple_adapted_function<
        &ssl_api::evp_digest_sign_final,
        c_api::head_transformed<size_t, 3, 2>(message_digest, memory::block)>>;

    struct : _message_digest_sign_final_t {
        using base = _message_digest_sign_final_t;
        using base::base;

        constexpr auto required_size(message_digest mdc) const noexcept {
            size_t size{0};
            return base::operator()(mdc, {}, size)
              .replaced_with(span_size(size));
        }
    } message_digest_sign_final{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_verify_init,
      c_api::returned<pkey_ctx>(
        message_digest,
        c_api::returned<pkey_ctx>,
        message_digest_type,
        engine,
        pkey)>
      message_digest_verify_init{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_verify_update,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_verify_update{*this};

    simple_adapted_function<
      &ssl_api::evp_digest_verify_final,
      c_api::collapsed<int>(message_digest, memory::const_block)>
      message_digest_verify_final{*this};

    simple_adapted_function<&ssl_api::x509_store_ctx_new, owned_x509_store_ctx()>
      new_x509_store_ctx{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::x509_store_ctx_init,
        c_api::collapsed<
          int>(x509_store_ctx, x509_store, x509, const object_stack<x509>&)>,
      simple_adapted_function<
        &ssl_api::x509_store_ctx_init,
        c_api::collapsed<int>(x509_store_ctx, x509_store, x509, c_api::defaulted)>>
      init_x509_store_ctx{*this};

    simple_adapted_function<
      &ssl_api::x509_store_ctx_set0_trusted_stack,
      c_api::collapsed<int>(x509_store_ctx, const object_stack<x509>&)>
      set_x509_store_trusted_stack{*this};

    simple_adapted_function<
      &ssl_api::x509_store_ctx_set0_verified_chain,
      c_api::collapsed<int>(x509_store_ctx, const object_stack<x509>&)>
      set_x509_store_verified_chain{*this};

    simple_adapted_function<
      &ssl_api::x509_store_ctx_set0_untrusted,
      c_api::collapsed<int>(x509_store_ctx, const object_stack<x509>&)>
      set_x509_store_untrusted{*this};

    simple_adapted_function<
      &ssl_api::x509_store_ctx_cleanup,
      c_api::collapsed<int>(x509_store_ctx)>
      cleanup_x509_store_ctx{*this};

    simple_adapted_function<
      &ssl_api::x509_store_ctx_free,
      void(owned_x509_store_ctx)>
      delete_x509_store_ctx{*this};

    simple_adapted_function<
      &ssl_api::x509_verify_cert,
      c_api::collapsed<int>(x509_store_ctx)>
      x509_verify_certificate{*this};

    simple_adapted_function<&ssl_api::x509_store_new, owned_x509_store()>
      new_x509_store{*this};

    adapted_function<
      &ssl_api::x509_store_up_ref,
      owned_x509_store(x509_store),
      c_api::replaced_with_map<1>>
      copy_x509_store{*this};

    simple_adapted_function<&ssl_api::x509_store_free, void(owned_x509_store)>
      delete_x509_store{*this};

    simple_adapted_function<
      &ssl_api::x509_store_add_cert,
      c_api::collapsed<int>(x509_store, x509)>
      add_cert_into_x509_store{*this};

    simple_adapted_function<
      &ssl_api::x509_store_add_crl,
      c_api::collapsed<int>(x509_store, x509_crl)>
      add_crl_into_x509_store{*this};

    simple_adapted_function<
      &ssl_api::x509_store_load_locations,
      c_api::collapsed<int>(x509_store, string_view)>
      load_into_x509_store{*this};

    simple_adapted_function<&ssl_api::x509_crl_new, owned_x509_crl()>
      new_x509_crl{*this};

    simple_adapted_function<&ssl_api::x509_crl_free, void(owned_x509_crl)>
      delete_x509_crl{*this};

    simple_adapted_function<&ssl_api::x509_new, owned_x509()> new_x509{*this};

    simple_adapted_function<&ssl_api::x509_get_pubkey, owned_pkey(x509)>
      get_x509_pubkey{*this};

    simple_adapted_function<&ssl_api::x509_get0_serial_number, asn1_integer(x509)>
      get_x509_serial_number{*this};

    simple_adapted_function<&ssl_api::x509_get_issuer_name, x509_name(x509)>
      get_x509_issuer_name{*this};

    simple_adapted_function<&ssl_api::x509_get_subject_name, x509_name(x509)>
      get_x509_subject_name{*this};

    simple_adapted_function<&ssl_api::x509_free, void(owned_x509)> delete_x509{
      *this};

    simple_adapted_function<
      &ssl_api::x509_name_entry_count,
      span_size_t(x509_name)>
      get_name_entry_count{*this};

    simple_adapted_function<
      &ssl_api::x509_name_get_entry,
      x509_name_entry(x509_name, span_size_t)>
      get_name_entry{*this};

    simple_adapted_function<
      &ssl_api::x509_name_entry_get_object,
      asn1_object(x509_name_entry)>
      get_name_entry_object{*this};

    simple_adapted_function<
      &ssl_api::x509_name_entry_get_data,
      asn1_string(x509_name_entry)>
      get_name_entry_data{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::pem_read_bio_private_key,
        owned_pkey(basic_io, pkey&, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_private_key,
        owned_pkey(basic_io, c_api::defaulted, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_private_key,
        owned_pkey(basic_io, c_api::defaulted, c_api::defaulted, c_api::defaulted)>>
      read_bio_private_key{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::pem_read_bio_pubkey,
        owned_pkey(basic_io, pkey&, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_pubkey,
        owned_pkey(basic_io, c_api::defaulted, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_pubkey,
        owned_pkey(basic_io, c_api::defaulted, c_api::defaulted, c_api::defaulted)>>
      read_bio_public_key{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::pem_read_bio_x509_crl,
        owned_x509_crl(basic_io, x509_crl&, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_x509_crl,
        owned_x509_crl(basic_io, c_api::defaulted, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_x509_crl,
        owned_x509_crl(
          basic_io,
          c_api::defaulted,
          c_api::defaulted,
          c_api::defaulted)>>
      read_bio_x509_crl{*this};

    c_api::combined<
      simple_adapted_function<
        &ssl_api::pem_read_bio_x509,
        owned_x509(basic_io, x509&, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_x509,
        owned_x509(basic_io, c_api::defaulted, password_callback)>,
      simple_adapted_function<
        &ssl_api::pem_read_bio_x509,
        owned_x509(basic_io, c_api::defaulted, c_api::defaulted, c_api::defaulted)>>
      read_bio_x509{*this};

    basic_ssl_operations(api_traits& traits)
      : ssl_api{traits} {}
};
//------------------------------------------------------------------------------
export template <typename ApiTraits>
class basic_ssl_api
  : protected ApiTraits
  , public basic_ssl_operations<ApiTraits>
  , public basic_ssl_constants<ApiTraits> {
public:
    template <typename R>
    using combined_result = typename ApiTraits::template combined_result<R>;

    using evp_md_type = ssl_types::evp_md_type;

    basic_ssl_api(ApiTraits traits)
      : ApiTraits{std::move(traits)}
      , basic_ssl_operations<ApiTraits>{*static_cast<ApiTraits*>(this)}
      , basic_ssl_constants<ApiTraits>{
          *static_cast<ApiTraits*>(this),
          *static_cast<basic_ssl_operations<ApiTraits>*>(this)} {}

    basic_ssl_api()
      : basic_ssl_api{ApiTraits{}} {}

    auto data_digest(
      const memory::const_block data,
      memory::block dst,
      const message_digest_type mdtype) const noexcept -> memory::block {
        if(mdtype) {
            const auto req_size = this->message_digest_size(mdtype).value_or(0);

            if(dst.size() >= span_size(req_size)) {
                if(ok mdctx{this->new_message_digest()}) {
                    const auto cleanup{this->delete_message_digest.raii(mdctx)};

                    this->message_digest_init(mdctx, mdtype);
                    this->message_digest_update(mdctx, data);
                    return this->message_digest_final(mdctx, dst).or_default();
                }
            }
        }
        return {};
    }

    template <typename OptMdt>
    auto do_data_digest(
      const memory::const_block data,
      memory::block dst,
      OptMdt opt_mdtype) const noexcept -> memory::block {
        if(opt_mdtype) {
            return data_digest(data, dst, extract(opt_mdtype));
        }
        return {};
    }

    auto md5_digest(const memory::const_block data, memory::block dst)
      const noexcept {
        return do_data_digest(data, dst, this->message_digest_md5());
    }

    auto sha1_digest(const memory::const_block data, memory::block dst)
      const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha1());
    }

    auto sha224_digest(const memory::const_block data, memory::block dst)
      const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha224());
    }

    auto sha256_digest(const memory::const_block data, memory::block dst)
      const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha256());
    }

    auto sha384_digest(const memory::const_block data, memory::block dst)
      const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha384());
    }

    auto sha512_digest(const memory::const_block data, memory::block dst)
      const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha512());
    }

    auto sign_data_digest(
      const memory::const_block data,
      memory::block dst,
      const message_digest_type mdtype,
      const pkey pky) const noexcept -> memory::block {
        if(mdtype and pky) {
            if(ok mdctx{this->new_message_digest()}) {
                const auto cleanup{this->delete_message_digest.raii(mdctx)};

                if(this->message_digest_sign_init(
                     mdctx, mdtype, engine{}, pky)) {
                    if(this->message_digest_sign_update(mdctx, data)) {
                        return this->message_digest_sign_final(mdctx, dst)
                          .or_default();
                    }
                }
            }
        }
        return {};
    }

    auto verify_data_digest(
      const memory::const_block data,
      const memory::const_block sig,
      const message_digest_type mdtype,
      const pkey pky) const noexcept -> bool {
        if(mdtype and pky) {
            if(ok mdctx{this->new_message_digest()}) {
                const auto cleanup{this->delete_message_digest.raii(mdctx)};

                if(this->message_digest_verify_init(
                     mdctx, mdtype, engine{}, pky)) {
                    if(this->message_digest_verify_update(mdctx, data)) {
                        return bool(
                          this->message_digest_verify_final(mdctx, sig));
                    }
                }
            }
        }
        return false;
    }

    auto parse_private_key(
      const memory::const_block blk,
      password_callback get_passwd = {}) const noexcept
      -> combined_result<owned_pkey> {
        if(ok mbio{this->new_block_basic_io(blk)}) {
            const auto del_bio{this->delete_basic_io.raii(mbio)};

            return this->read_bio_private_key(mbio, get_passwd);
        }

        return {owned_pkey{}};
    }

    auto parse_public_key(
      const memory::const_block blk,
      password_callback get_passwd = {}) const noexcept
      -> combined_result<owned_pkey> {
        if(ok mbio{this->new_block_basic_io(blk)}) {
            const auto del_bio{this->delete_basic_io.raii(mbio)};

            return this->read_bio_public_key(mbio, get_passwd);
        }

        return {owned_pkey{}};
    }

    auto parse_x509(
      const memory::const_block blk,
      password_callback get_passwd = {}) const noexcept
      -> combined_result<owned_x509> {
        if(ok mbio{this->new_block_basic_io(blk)}) {
            const auto del_bio{this->delete_basic_io.raii(mbio)};

            return this->read_bio_x509(mbio, get_passwd);
        }

        return {};
    }

    auto ca_verify_certificate(const string_view ca_file_path, const x509 cert)
      const noexcept -> bool {
        if(ok store{this->new_x509_store()}) {
            const auto del_store{this->delete_x509_store.raii(store)};

            if(this->load_into_x509_store(store, ca_file_path)) {
                if(ok vrfy_ctx{this->new_x509_store_ctx()}) {
                    const auto del_vrfy{
                      this->delete_x509_store_ctx.raii(vrfy_ctx)};

                    if(this->init_x509_store_ctx(vrfy_ctx, store, cert)) {
                        if(ok verify_res{
                             this->x509_verify_certificate(vrfy_ctx)}) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    auto ca_verify_certificate(const x509 ca_cert, const x509 cert)
      const noexcept -> bool {
        if(ok store{this->new_x509_store()}) {
            const auto del_store{this->delete_x509_store.raii(store)};

            if(this->add_cert_into_x509_store(store, ca_cert)) {
                if(ok vrfy_ctx{this->new_x509_store_ctx()}) {
                    const auto del_vrfy{
                      this->delete_x509_store_ctx.raii(vrfy_ctx)};

                    if(this->init_x509_store_ctx(vrfy_ctx, store, cert)) {
                        if(ok verify_res{
                             this->x509_verify_certificate(vrfy_ctx)}) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    auto find_name_entry(
      const x509_name name,
      const string_view ent_name,
      const bool no_name = false) const noexcept -> string_view {
        const auto count{extract(this->get_name_entry_count(name))};
        std::array<char, 256> namebuf{};
        for(const auto index : integer_range(count)) {
            if(const auto entry{this->get_name_entry(name, index)}) {
                if(const auto object{
                     this->get_name_entry_object(extract(entry))}) {
                    const auto cur_name{this->object_to_text(
                      cover(namebuf), extract(object), no_name)};
                    if(are_equal(extract(cur_name), ent_name)) {
                        if(const auto data{
                             this->get_name_entry_data(extract(entry))}) {
                            return this->get_string_view(extract(data));
                        }
                    }
                }
            }
        }
        return {};
    }

    auto find_name_oid_entry(
      const x509_name name,
      const string_view ent_name,
      const string_view ent_oid) const noexcept -> string_view {
        const auto count{extract(this->get_name_entry_count(name))};
        std::array<char, 256> namebuf{};
        for(const auto index : integer_range(count)) {
            if(const auto entry{this->get_name_entry(name, index)}) {
                if(const auto object{
                     this->get_name_entry_object(extract(entry))}) {
                    if(are_equal(
                         this
                           ->object_to_text(
                             cover(namebuf), extract(object), false)
                           .or_default(),
                         ent_name)) {
                        if(const auto data{
                             this->get_name_entry_data(extract(entry))}) {
                            return this->get_string_view(extract(data));
                        }
                    }
                    if(are_equal(
                         this
                           ->object_to_text(
                             cover(namebuf), extract(object), true)
                           .or_default(),
                         ent_oid)) {
                        if(const auto data{
                             this->get_name_entry_data(extract(entry))}) {
                            return this->get_string_view(extract(data));
                        }
                    }
                }
            }
        }
        return {};
    }

    auto find_certificate_issuer_name_entry(
      const x509 cert,
      const string_view ent_name) const noexcept -> string_view {
        if(const auto isuname{this->get_x509_issuer_name(cert)}) {
            return find_name_entry(extract(isuname), ent_name);
        }
        return {};
    }

    auto find_certificate_subject_name_entry(
      const x509 cert,
      const string_view ent_name) const noexcept -> string_view {
        if(const auto subname{this->get_x509_subject_name(cert)}) {
            return this->find_name_entry(extract(subname), ent_name);
        }
        return {};
    }

    auto find_certificate_subject_name_entry(
      const x509 cert,
      const string_view ent_name,
      const string_view ent_oid) const noexcept -> string_view {
        if(const auto subname{this->get_x509_subject_name(cert)}) {
            return this->find_name_oid_entry(
              extract(subname), ent_name, ent_oid);
        }
        return {};
    }

    auto certificate_subject_name_has_entry_value(
      const x509 cert,
      const string_view ent_name,
      const string_view value) const noexcept -> bool {
        return are_equal(
          this->find_certificate_subject_name_entry(cert, ent_name), value);
    }

    auto certificate_subject_name_has_entry_value(
      const x509 cert,
      const string_view ent_name,
      const string_view ent_oid,
      const string_view value) const noexcept -> bool {
        return are_equal(
          this->find_certificate_subject_name_entry(cert, ent_name, ent_oid),
          value);
    }
};
//------------------------------------------------------------------------------
export template <std::size_t I, typename ApiTraits>
auto get(basic_ssl_api<ApiTraits>& x) noexcept ->
  typename std::tuple_element<I, basic_ssl_api<ApiTraits>>::type& {
    return x;
}

export template <std::size_t I, typename ApiTraits>
auto get(const basic_ssl_api<ApiTraits>& x) noexcept -> const
  typename std::tuple_element<I, basic_ssl_api<ApiTraits>>::type& {
    return x;
}
//------------------------------------------------------------------------------
export using ssl_api = basic_ssl_api<ssl_api_traits>;
} // namespace eagine::sslplus
// NOLINTNEXTLINE(cert-dcl58-cpp)
namespace std {
//------------------------------------------------------------------------------
export template <typename ApiTraits>
struct tuple_size<eagine::sslplus::basic_ssl_api<ApiTraits>>
  : public std::integral_constant<std::size_t, 2> {};

export template <typename ApiTraits>
struct tuple_element<0, eagine::sslplus::basic_ssl_api<ApiTraits>> {
    using type = eagine::sslplus::basic_ssl_operations<ApiTraits>;
};

export template <typename ApiTraits>
struct tuple_element<1, eagine::sslplus::basic_ssl_api<ApiTraits>> {
    using type = eagine::sslplus::basic_ssl_constants<ApiTraits>;
};
//------------------------------------------------------------------------------
} // namespace std

