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
#include <eagine/c_api_wrap.hpp>
#include <eagine/callable_ref.hpp>
#include <eagine/memory/split_block.hpp>
#include <eagine/scope_exit.hpp>
#include <eagine/string_list.hpp>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
#define SSLPAFP(FUNC) decltype(ssl_api::FUNC), &ssl_api::FUNC
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
//------------------------------------------------------------------------------
template <typename ApiTraits>
class basic_ssl_operations : public basic_ssl_c_api<ApiTraits> {

public:
    using api_traits = ApiTraits;
    using ssl_api = basic_ssl_c_api<ApiTraits>;

    struct collapse_bool_map {
        template <typename... P>
        constexpr auto operator()(size_constant<0> i, P&&... p) const noexcept {
            return collapse_bool(
              c_api::trivial_map{}(i, std::forward<P>(p)...));
        }
    };

    template <typename W, W ssl_api::*F, typename Signature = typename W::signature>
    class func;

    template <typename W, W ssl_api::*F, typename RVC, typename... Params>
    class func<W, F, RVC(Params...)>
      : public wrapped_c_api_function<ssl_api, api_traits, nothing_t, W, F> {
        using base =
          wrapped_c_api_function<ssl_api, api_traits, nothing_t, W, F>;

    private:
        template <typename Res>
        constexpr auto _check(Res&& res) const noexcept {
            res.error_code(this->api().err_get_error());
            return std::forward<Res>(res);
        }

    protected:
        template <typename... Args>
        constexpr auto _chkcall(Args&&... args) const noexcept {
            return this->_check(this->_call(std::forward<Args>(args)...));
        }

        using base::_conv;

        template <typename... Args>
        constexpr auto _cnvchkcall(Args&&... args) const noexcept {
            return this->_chkcall(_conv(args)...).cast_to(type_identity<RVC>{});
        }

    public:
        using base::base;

        constexpr auto operator()(Params... params) const noexcept {
            return this->_chkcall(_conv(params)...)
              .cast_to(type_identity<RVC>{});
        }

        constexpr auto fake() const noexcept {
            auto result{this->_fake(0)};
            result.set_unknown_error();
            return result;
        }
    };

    c_api::adapted_function<&ssl_api::ui_null, ui_method()> null_ui{*this};
    c_api::adapted_function<&ssl_api::ui_openssl, ui_method()> openssl_ui{
      *this};

    c_api::adapted_function<&ssl_api::engine_load_builtin_engines>
      load_builtin_engines{*this};

    c_api::adapted_function<&ssl_api::engine_get_first, owned_engine()>
      get_first_engine{*this};

    c_api::adapted_function<&ssl_api::engine_get_last, owned_engine()>
      get_last_engine{*this};

    c_api::
      adapted_function<&ssl_api::engine_get_next, owned_engine(owned_engine&)>
        get_next_engine{*this};

    c_api::
      adapted_function<&ssl_api::engine_get_prev, owned_engine(owned_engine&)>
        get_prev_engine{*this};

    c_api::adapted_function<&ssl_api::engine_new, owned_engine()> new_engine{
      *this};

    c_api::adapted_function<&ssl_api::engine_by_id, owned_engine(string_view)>
      open_engine{*this};

    c_api::adapted_function<
      &ssl_api::engine_up_ref,
      owned_engine(engine),
      c_api::replaced_with_map<1>>
      copy_engine{*this};

    c_api::adapted_function<
      &ssl_api::engine_free,
      int(owned_engine&),
      collapse_bool_map>
      delete_engine{*this};

    c_api::adapted_function<&ssl_api::engine_init, int(engine), collapse_bool_map>
      init_engine{*this};

    c_api::
      adapted_function<&ssl_api::engine_finish, int(engine), collapse_bool_map>
        finish_engine{*this};

    c_api::adapted_function<&ssl_api::engine_get_id, string_view(engine)>
      get_engine_id{*this};

    c_api::adapted_function<&ssl_api::engine_get_name, string_view(engine)>
      get_engine_name{*this};

    c_api::adapted_function<
      &ssl_api::engine_set_default_rsa,
      int(engine),
      collapse_bool_map>
      set_default_rsa{*this};

    c_api::adapted_function<
      &ssl_api::engine_set_default_dsa,
      int(engine),
      collapse_bool_map>
      set_default_dsa{*this};

    c_api::adapted_function<
      &ssl_api::engine_set_default_dh,
      int(engine),
      collapse_bool_map>
      set_default_dh{*this};

    c_api::adapted_function<
      &ssl_api::engine_set_default_rand,
      int(engine),
      collapse_bool_map>
      set_default_rand{*this};

    c_api::adapted_function<
      &ssl_api::engine_set_default_ciphers,
      int(engine),
      collapse_bool_map>
      set_default_ciphers{*this};

    c_api::adapted_function<
      &ssl_api::engine_set_default_digests,
      int(engine),
      collapse_bool_map>
      set_default_digests{*this};

    c_api::adapted_function<
      &ssl_api::engine_load_private_key,
      owned_pkey(engine, string_view, ui_method)>
      load_engine_private_key{*this};

    c_api::adapted_function<
      &ssl_api::engine_load_public_key,
      owned_pkey(engine, string_view)>
      load_engine_public_key{*this};

    // ASN1
    // string
    c_api::
      adapted_function<&ssl_api::asn1_string_length, span_size_t(asn1_string)>
        get_string_length{*this};

    c_api::adapted_function<
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

    c_api::adapted_function<
      &ssl_api::asn1_integer_get_int64,
      std::int64_t(asn1_integer)>
      get_int64{*this};

    c_api::adapted_function<
      &ssl_api::asn1_integer_get_uint64,
      std::uint64_t(asn1_integer)>
      get_uint64{*this};

    // object_to_text
    struct : func<SSLPAFP(obj_obj2txt)> {
        using func<SSLPAFP(obj_obj2txt)>::func;

        constexpr auto operator()(
          string_span dst,
          asn1_object obj,
          bool no_name = false) const noexcept {
            return head(
              dst,
              extract_or(
                this->_cnvchkcall(
                  dst.data(), limit_cast<int>(dst.size()), obj, no_name ? 1 : 0),
                0));
        }
    } object_to_text;

    c_api::adapted_function<&ssl_api::bio_new, owned_basic_io(basic_io_method)>
      new_basic_io{*this};

    c_api::adapted_function<
      &ssl_api::bio_new_mem_buf,
      owned_basic_io(memory::const_block)>
      new_block_basic_io{*this};

    c_api::adapted_function<
      &ssl_api::bio_free,
      int(owned_basic_io&),
      collapse_bool_map>
      delete_basic_io{*this};

    c_api::adapted_function<
      &ssl_api::bio_free_all,
      int(owned_basic_io&),
      collapse_bool_map>
      delete_all_basic_ios{*this};

    c_api::adapted_function<
      &ssl_api::rand_bytes,
      int(memory::block),
      collapse_bool_map>
      random_bytes{*this};

    c_api::adapted_function<&ssl_api::evp_pkey_up_ref, owned_pkey(pkey)>
      copy_pkey{*this};

    c_api::adapted_function<
      &ssl_api::evp_pkey_free,
      int(owned_pkey&),
      collapse_bool_map>
      delete_pkey{*this};

    c_api::adapted_function<&ssl_api::evp_aes_128_ctr, cipher_type()>
      cipher_aes_128_ctr{*this};

    c_api::adapted_function<&ssl_api::evp_aes_128_ccm, cipher_type()>
      cipher_aes_128_ccm{*this};

    c_api::adapted_function<&ssl_api::evp_aes_128_gcm, cipher_type()>
      cipher_aes_128_gcm{*this};

    c_api::adapted_function<&ssl_api::evp_aes_128_xts, cipher_type()>
      cipher_aes_128_xts{*this};

    c_api::adapted_function<&ssl_api::evp_aes_192_ecb, cipher_type()>
      cipher_aes_192_ecb{*this};

    c_api::adapted_function<&ssl_api::evp_aes_192_cbc, cipher_type()>
      cipher_aes_192_cbc{*this};

    c_api::adapted_function<&ssl_api::evp_cipher_ctx_new, owned_cipher()>
      new_cipher{*this};

    c_api::adapted_function<
      &ssl_api::evp_cipher_ctx_free,
      int(owned_cipher&),
      collapse_bool_map>
      delete_cipher{*this};

    c_api::adapted_function<
      &ssl_api::evp_cipher_ctx_reset,
      int(cipher),
      collapse_bool_map>
      cipher_reset{*this};

    c_api::adapted_function<
      &ssl_api::evp_cipher_init,
      int(cipher, cipher_type, memory::const_block, memory::const_block, bool),
      collapse_bool_map>
      cipher_init{*this};

    c_api::adapted_function<
      &ssl_api::evp_cipher_init_ex,
      int(
        cipher,
        cipher_type,
        engine,
        memory::const_block,
        memory::const_block,
        bool),
      collapse_bool_map>
      cipher_init_ex{*this};

    // cipher_update
    struct : func<SSLPAFP(evp_cipher_update)> {
        using func<SSLPAFP(evp_cipher_update)>::func;

        constexpr auto operator()(
          cipher cyc,
          memory::split_block out,
          memory::const_block in) const noexcept {
            int outl{0};
            return this
              ->_cnvchkcall(
                cyc,
                out.tail().data(),
                &outl,
                in.data(),
                limit_cast<int>(in.size()))
              .replaced_with(out.advance(span_size(outl)));
        }

    } cipher_update;

    // cipher_final
    struct : func<SSLPAFP(evp_cipher_final)> {
        using func<SSLPAFP(evp_cipher_final)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } cipher_final;

    // cipher_final_ex
    struct : func<SSLPAFP(evp_cipher_final_ex)> {
        using func<SSLPAFP(evp_cipher_final_ex)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } cipher_final_ex;

    c_api::adapted_function<
      &ssl_api::evp_encrypt_init,
      int(cipher, cipher_type, memory::const_block, memory::const_block, bool),
      collapse_bool_map>
      encrypt_init{*this};

    c_api::adapted_function<
      &ssl_api::evp_encrypt_init_ex,
      int(
        cipher,
        cipher_type,
        engine,
        memory::const_block,
        memory::const_block,
        bool),
      collapse_bool_map>
      encrypt_init_ex{*this};

    // encrypt_update
    struct : func<SSLPAFP(evp_encrypt_update)> {
        using func<SSLPAFP(evp_encrypt_update)>::func;

        constexpr auto operator()(
          cipher cyc,
          memory::split_block out,
          memory::const_block in) const noexcept {
            int outl{0};
            return this
              ->_cnvchkcall(
                cyc,
                out.tail().data(),
                &outl,
                in.data(),
                limit_cast<int>(in.size()))
              .replaced_with(out.advance(span_size(outl)));
        }

    } encrypt_update;

    // encrypt_final
    struct : func<SSLPAFP(evp_encrypt_final)> {
        using func<SSLPAFP(evp_encrypt_final)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } encrypt_final;

    // encrypt_final_ex
    struct : func<SSLPAFP(evp_encrypt_final_ex)> {
        using func<SSLPAFP(evp_encrypt_final_ex)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } encrypt_final_ex;

    c_api::adapted_function<
      &ssl_api::evp_decrypt_init,
      int(cipher, cipher_type, memory::const_block, memory::const_block, bool),
      collapse_bool_map>
      decrypt_init{*this};

    c_api::adapted_function<
      &ssl_api::evp_decrypt_init_ex,
      int(
        cipher,
        cipher_type,
        engine,
        memory::const_block,
        memory::const_block,
        bool),
      collapse_bool_map>
      decrypt_init_ex{*this};

    // decrypt_update
    struct : func<SSLPAFP(evp_decrypt_update)> {
        using func<SSLPAFP(evp_decrypt_update)>::func;

        constexpr auto operator()(
          cipher cyc,
          memory::split_block out,
          memory::const_block in) const noexcept {
            int outl{0};
            return this
              ->_cnvchkcall(
                cyc,
                out.tail().data(),
                &outl,
                in.data(),
                limit_cast<int>(in.size()))
              .replaced_with(out.advance(span_size(outl)));
        }

    } decrypt_update;

    // decrypt_final
    struct : func<SSLPAFP(evp_decrypt_final)> {
        using func<SSLPAFP(evp_decrypt_final)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } decrypt_final;

    // decrypt_final_ex
    struct : func<SSLPAFP(evp_decrypt_final_ex)> {
        using func<SSLPAFP(evp_decrypt_final_ex)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } decrypt_final_ex;

    // message_digest
    c_api::adapted_function<&ssl_api::evp_md_null, message_digest_type()>
      message_digest_noop{*this};

    c_api::adapted_function<&ssl_api::evp_md5, message_digest_type()>
      message_digest_md5{*this};

    c_api::adapted_function<&ssl_api::evp_sha1, message_digest_type()>
      message_digest_sha1{*this};

    c_api::adapted_function<&ssl_api::evp_sha224, message_digest_type()>
      message_digest_sha224{*this};

    c_api::adapted_function<&ssl_api::evp_sha256, message_digest_type()>
      message_digest_sha256{*this};

    c_api::adapted_function<&ssl_api::evp_sha384, message_digest_type()>
      message_digest_sha384{*this};

    c_api::adapted_function<&ssl_api::evp_sha512, message_digest_type()>
      message_digest_sha512{*this};

    c_api::
      adapted_function<&ssl_api::evp_md_size, span_size_t(message_digest_type)>
        message_digest_size{*this};

    c_api::adapted_function<&ssl_api::evp_md_ctx_new, owned_message_digest()>
      new_message_digest{*this};

    c_api::adapted_function<
      &ssl_api::evp_md_ctx_free,
      int(owned_message_digest&),
      collapse_bool_map>
      delete_message_digest{*this};

    c_api::adapted_function<
      &ssl_api::evp_md_ctx_reset,
      int(message_digest),
      collapse_bool_map>
      message_digest_reset{*this};

    c_api::adapted_function<
      &ssl_api::evp_digest_init,
      int(message_digest, message_digest_type),
      collapse_bool_map>
      message_digest_init{*this};

    c_api::adapted_function<
      &ssl_api::evp_digest_init_ex,
      int(message_digest, message_digest_type, engine),
      collapse_bool_map>
      message_digest_init_ex{*this};

    c_api::adapted_function<
      &ssl_api::evp_digest_update,
      int(message_digest, memory::const_block),
      collapse_bool_map>
      message_digest_update{*this};

    // message_digest_final
    struct : func<SSLPAFP(evp_digest_final)> {
        using func<SSLPAFP(evp_digest_final)>::func;

        constexpr auto operator()(message_digest mdc, memory::block blk)
          const noexcept {
            unsigned int size{0U};
            return this->_cnvchkcall(mdc, blk.data(), &size)
              .replaced_with(head(blk, span_size(size)));
        }
    } message_digest_final;

    // message_digest_final_ex
    struct : func<SSLPAFP(evp_digest_final_ex)> {
        using func<SSLPAFP(evp_digest_final_ex)>::func;

        constexpr auto operator()(message_digest mdc, memory::block blk)
          const noexcept {
            unsigned int size{0U};
            return this->_cnvchkcall(mdc, blk.data(), &size)
              .replaced_with(head(blk, span_size(size)));
        }
    } message_digest_final_ex;

    // message_digest_sign_init
    struct : func<SSLPAFP(evp_digest_sign_init)> {
        using func<SSLPAFP(evp_digest_sign_init)>::func;

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, nullptr, pky);
        }

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          engine eng,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, eng, pky);
        }
    } message_digest_sign_init;

    c_api::adapted_function<
      &ssl_api::evp_digest_sign_update,
      int(message_digest, memory::const_block),
      collapse_bool_map>
      message_digest_sign_update{*this};

    // message_digest_sign_final
    struct : func<SSLPAFP(evp_digest_sign_final)> {
        using func<SSLPAFP(evp_digest_sign_final)>::func;

        constexpr auto required_size(message_digest mdc) const noexcept {
            size_t size{0U};
            return this->_cnvchkcall(mdc, nullptr, &size)
              .replaced_with(span_size(size));
        }

        constexpr auto operator()(message_digest mdc, memory::block blk)
          const noexcept {
            auto size = limit_cast<size_t>(blk.size());
            return this->_cnvchkcall(mdc, blk.data(), &size)
              .replaced_with(head(blk, span_size(size)));
        }
    } message_digest_sign_final;

    // message_digest_verify_init
    struct : func<SSLPAFP(evp_digest_verify_init)> {
        using func<SSLPAFP(evp_digest_verify_init)>::func;

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, nullptr, pky);
        }

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          engine eng,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, eng, pky);
        }
    } message_digest_verify_init;

    c_api::adapted_function<
      &ssl_api::evp_digest_verify_update,
      int(message_digest, memory::const_block),
      collapse_bool_map>
      message_digest_verify_update{*this};

    c_api::adapted_function<
      &ssl_api::evp_digest_verify_final,
      int(message_digest, memory::const_block),
      collapse_bool_map>
      message_digest_verify_final{*this};

    c_api::adapted_function<&ssl_api::x509_store_ctx_new, owned_x509_store_ctx()>
      new_x509_store_ctx{*this};

    using _init_x509_store_ctx_t = c_api::adapted_function<
      &ssl_api::x509_store_ctx_init,
      int(x509_store_ctx, x509_store, x509, const object_stack<x509>&),
      collapse_bool_map>;

    struct : _init_x509_store_ctx_t {
        using base = _init_x509_store_ctx_t;
        using base::base;
        using base::operator();

        constexpr auto operator()(x509_store_ctx ctx, x509_store xst, x509 crt)
          const noexcept {
            return (*this)(ctx, xst, crt, object_stack<x509>{});
        }

    } init_x509_store_ctx{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_ctx_set0_trusted_stack,
      int(x509_store_ctx, const object_stack<x509>&),
      collapse_bool_map>
      set_x509_store_trusted_stack{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_ctx_set0_verified_chain,
      int(x509_store_ctx, const object_stack<x509>&),
      collapse_bool_map>
      set_x509_store_verified_chain{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_ctx_set0_untrusted,
      int(x509_store_ctx, const object_stack<x509>&),
      collapse_bool_map>
      set_x509_store_untrusted{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_ctx_cleanup,
      int(x509_store_ctx),
      collapse_bool_map>
      cleanup_x509_store_ctx{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_ctx_free,
      int(owned_x509_store_ctx&),
      collapse_bool_map>
      delete_x509_store_ctx{*this};

    c_api::adapted_function<
      &ssl_api::x509_verify_cert,
      int(x509_store_ctx),
      collapse_bool_map>
      x509_verify_certificate{*this};

    c_api::adapted_function<&ssl_api::x509_store_new, owned_x509_store()>
      new_x509_store{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_up_ref,
      owned_x509_store(x509_store),
      c_api::replaced_with_map<1>>
      copy_x509_store{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_free,
      int(owned_x509_store&),
      collapse_bool_map>
      delete_x509_store{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_add_cert,
      int(x509_store, x509),
      collapse_bool_map>
      add_cert_into_x509_store{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_add_crl,
      int(x509_store, x509_crl),
      collapse_bool_map>
      add_crl_into_x509_store{*this};

    c_api::adapted_function<
      &ssl_api::x509_store_load_locations,
      int(x509_store, string_view),
      collapse_bool_map>
      load_into_x509_store{*this};

    c_api::adapted_function<&ssl_api::x509_crl_new, owned_x509_crl()>
      new_x509_crl{*this};

    c_api::adapted_function<
      &ssl_api::x509_crl_free,
      int(owned_x509_crl&),
      collapse_bool_map>
      delete_x509_crl{*this};

    c_api::adapted_function<&ssl_api::x509_new, owned_x509()> new_x509{*this};

    c_api::adapted_function<&ssl_api::x509_get_pubkey, owned_pkey(x509)>
      get_x509_pubkey{*this};

    c_api::adapted_function<&ssl_api::x509_get0_serial_number, asn1_integer(x509)>
      get_x509_serial_number{*this};

    c_api::adapted_function<&ssl_api::x509_get_issuer_name, x509_name(x509)>
      get_x509_issuer_name{*this};

    c_api::adapted_function<&ssl_api::x509_get_subject_name, x509_name(x509)>
      get_x509_subject_name{*this};

    c_api::
      adapted_function<&ssl_api::x509_free, int(owned_x509&), collapse_bool_map>
        delete_x509{*this};

    c_api::
      adapted_function<&ssl_api::x509_name_entry_count, span_size_t(x509_name)>
        get_name_entry_count{*this};

    c_api::adapted_function<
      &ssl_api::x509_name_get_entry,
      x509_name_entry(x509_name, span_size_t)>
      get_name_entry{*this};

    c_api::adapted_function<
      &ssl_api::x509_name_entry_get_object,
      asn1_object(x509_name_entry)>
      get_name_entry_object{*this};

    c_api::adapted_function<
      &ssl_api::x509_name_entry_get_data,
      asn1_string(x509_name_entry)>
      get_name_entry_data{*this};

    // read_bio_private_key
    struct : func<SSLPAFP(pem_read_bio_private_key)> {
        using func<SSLPAFP(pem_read_bio_private_key)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_pkey>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_pkey>{});
        }

    } read_bio_private_key;

    // read_bio_public_key
    struct : func<SSLPAFP(pem_read_bio_pubkey)> {
        using func<SSLPAFP(pem_read_bio_pubkey)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_pkey>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_pkey>{});
        }

    } read_bio_public_key;

    // read_bio_x509_crl
    struct : func<SSLPAFP(pem_read_bio_x509_crl)> {
        using func<SSLPAFP(pem_read_bio_x509_crl)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_x509_crl>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_x509_crl>{});
        }

    } read_bio_x509_crl;

    // read_bio_x509
    struct : func<SSLPAFP(pem_read_bio_x509)> {
        using func<SSLPAFP(pem_read_bio_x509)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_x509>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_x509>{});
        }

    } read_bio_x509;

    basic_ssl_operations(api_traits& traits);
};
//------------------------------------------------------------------------------
#undef SSLPAFP
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif // EAGINE_SSLPLUS_API_API_HPP
