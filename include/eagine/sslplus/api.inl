/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#include <eagine/sslplus/api/c_api.inl>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
template <typename ApiTraits>
inline auto basic_ssl_api<ApiTraits>::data_digest(
  const memory::const_block data,
  memory::block dst,
  const message_digest_type mdtype) const noexcept -> memory::block {
    if(mdtype) {
        const auto req_size = extract_or(this->message_digest_size(mdtype), 0);

        if(dst.size() >= span_size(req_size)) {
            if(ok mdctx{this->new_message_digest()}) {
                const auto cleanup{this->delete_message_digest.raii(mdctx)};

                this->message_digest_init(mdctx, mdtype);
                this->message_digest_update(mdctx, data);
                return extract_or(
                  this->message_digest_final(mdctx, dst), memory::block{});
            }
        }
    }
    return {};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
inline auto basic_ssl_api<ApiTraits>::sign_data_digest(
  const memory::const_block data,
  memory::block dst,
  const message_digest_type mdtype,
  const pkey pky) const noexcept -> memory::block {
    if(mdtype && pky) {
        if(ok mdctx{this->new_message_digest()}) {
            const auto cleanup{this->delete_message_digest.raii(mdctx)};

            if(this->message_digest_sign_init(mdctx, mdtype, engine{}, pky)) {
                if(this->message_digest_sign_update(mdctx, data)) {
                    return extract_or(
                      this->message_digest_sign_final(mdctx, dst),
                      memory::block{});
                }
            }
        }
    }
    return {};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
inline auto basic_ssl_api<ApiTraits>::verify_data_digest(
  const memory::const_block data,
  const memory::const_block sig,
  const message_digest_type mdtype,
  const pkey pky) const noexcept -> bool {
    if(mdtype && pky) {
        if(ok mdctx{this->new_message_digest()}) {
            const auto cleanup{this->delete_message_digest.raii(mdctx)};

            if(this->message_digest_verify_init(mdctx, mdtype, engine{}, pky)) {
                if(this->message_digest_verify_update(mdctx, data)) {
                    return bool(this->message_digest_verify_final(mdctx, sig));
                }
            }
        }
    }
    return false;
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::parse_private_key(
  const memory::const_block blk,
  password_callback get_passwd) const noexcept -> combined_result<owned_pkey> {
    if(ok mbio{this->new_block_basic_io(blk)}) {
        const auto del_bio{this->delete_basic_io.raii(mbio)};

        return this->read_bio_private_key(mbio, get_passwd);
    }

    return {owned_pkey{}};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::parse_public_key(
  const memory::const_block blk,
  password_callback get_passwd) const noexcept -> combined_result<owned_pkey> {
    if(ok mbio{this->new_block_basic_io(blk)}) {
        const auto del_bio{this->delete_basic_io.raii(mbio)};

        return this->read_bio_public_key(mbio, get_passwd);
    }

    return {owned_pkey{}};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::parse_x509(
  const memory::const_block blk,
  password_callback get_passwd) const noexcept -> combined_result<owned_x509> {
    if(ok mbio{this->new_block_basic_io(blk)}) {
        const auto del_bio{this->delete_basic_io.raii(mbio)};

        return this->read_bio_x509(mbio, get_passwd);
    }

    return {owned_x509{}};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::ca_verify_certificate(
  const string_view ca_file_path,
  const x509 cert) const noexcept -> bool {
    if(ok store{this->new_x509_store()}) {
        const auto del_store{this->delete_x509_store.raii(store)};

        if(this->load_into_x509_store(store, ca_file_path)) {
            if(ok vrfy_ctx{this->new_x509_store_ctx()}) {
                const auto del_vrfy{this->delete_x509_store_ctx.raii(vrfy_ctx)};

                if(this->init_x509_store_ctx(vrfy_ctx, store, cert)) {
                    if(ok verify_res{this->x509_verify_certificate(vrfy_ctx)}) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::ca_verify_certificate(
  const x509 ca_cert,
  const x509 cert) const noexcept -> bool {
    if(ok store{this->new_x509_store()}) {
        const auto del_store{this->delete_x509_store.raii(store)};

        if(this->add_cert_into_x509_store(store, ca_cert)) {
            if(ok vrfy_ctx{this->new_x509_store_ctx()}) {
                const auto del_vrfy{this->delete_x509_store_ctx.raii(vrfy_ctx)};

                if(this->init_x509_store_ctx(vrfy_ctx, store, cert)) {
                    if(ok verify_res{this->x509_verify_certificate(vrfy_ctx)}) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::find_name_entry(
  const x509_name name,
  const string_view ent_name,
  const bool no_name) const noexcept -> string_view {
    const auto count{extract(this->get_name_entry_count(name))};
    std::array<char, 256> namebuf{};
    for(const auto index : integer_range(count)) {
        if(const auto entry{this->get_name_entry(name, index)}) {
            if(const auto object{this->get_name_entry_object(extract(entry))}) {
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
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::find_name_oid_entry(
  const x509_name name,
  const string_view ent_name,
  const string_view ent_oid) const noexcept -> string_view {
    const auto count{extract(this->get_name_entry_count(name))};
    std::array<char, 256> namebuf{};
    for(const auto index : integer_range(count)) {
        if(const auto entry{this->get_name_entry(name, index)}) {
            if(const auto object{this->get_name_entry_object(extract(entry))}) {
                if(are_equal(
                     extract_or(this->object_to_text(
                       cover(namebuf), extract(object), false)),
                     ent_name)) {
                    if(const auto data{
                         this->get_name_entry_data(extract(entry))}) {
                        return this->get_string_view(extract(data));
                    }
                }
                if(are_equal(
                     extract_or(this->object_to_text(
                       cover(namebuf), extract(object), true)),
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
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::find_certificate_issuer_name_entry(
  const x509 cert,
  const string_view ent_name) const noexcept -> string_view {
    if(const auto isuname{this->get_x509_issuer_name(cert)}) {
        return find_name_entry(extract(isuname), ent_name);
    }
    return {};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::find_certificate_subject_name_entry(
  const x509 cert,
  const string_view ent_name) const noexcept -> string_view {
    if(const auto subname{this->get_x509_subject_name(cert)}) {
        return this->find_name_entry(extract(subname), ent_name);
    }
    return {};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::find_certificate_subject_name_entry(
  const x509 cert,
  const string_view ent_name,
  const string_view ent_oid) const noexcept -> string_view {
    if(const auto subname{this->get_x509_subject_name(cert)}) {
        return this->find_name_oid_entry(extract(subname), ent_name, ent_oid);
    }
    return {};
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::certificate_subject_name_has_entry_value(
  const x509 cert,
  const string_view ent_name,
  const string_view value) const noexcept -> bool {
    return are_equal(
      this->find_certificate_subject_name_entry(cert, ent_name), value);
}
//------------------------------------------------------------------------------
template <typename ApiTraits>
auto basic_ssl_api<ApiTraits>::certificate_subject_name_has_entry_value(
  const x509 cert,
  const string_view ent_name,
  const string_view ent_oid,
  const string_view value) const noexcept -> bool {
    return are_equal(
      this->find_certificate_subject_name_entry(cert, ent_name, ent_oid),
      value);
}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
