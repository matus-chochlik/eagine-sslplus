/// @example eagine/sslplus/004_verify_cert.cpp
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#include <eagine/console/console.hpp>
#include <eagine/embed.hpp>
#include <eagine/file_contents.hpp>
#include <eagine/logging/logger.hpp>
#include <eagine/main.hpp>
#include <eagine/sslplus/openssl.hpp>

#include <eagine/sslplus/api.hpp>

#include <array>

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {

    string_view cert_path{"example.crt"};
    if(const auto arg{ctx.args().find("--cert").next()}) {
        cert_path = arg;
    }
    const memory::const_block ca_cert_pem{
      eagine::embed(EAGINE_ID(caCert), "example-ca.crt")};

    const sslplus::ssl_api ssl;

    if(ok ca_cert{ssl.parse_x509(ca_cert_pem, {})}) {
        const auto del_ca_cert{ssl.delete_x509.raii(ca_cert)};

        if(const auto subname{ssl.get_x509_subject_name(ca_cert)}) {
            const auto count{
              extract(ssl.get_name_entry_count(extract(subname)))};
            const auto entry_cio{
              ctx.cio()
                .print(EAGINE_ID(ssl), "CA certificate common name entries:")
                .to_be_continued()};

            for(const auto index : integer_range(count)) {
                if(const auto entry{
                     ssl.get_name_entry(extract(subname), index)}) {
                    const auto object{
                      ssl.get_name_entry_object(extract(entry))};
                    const auto value{ssl.get_name_entry_data(extract(entry))};

                    std::array<char, 96> namebuf{};
                    const auto name{ssl.object_to_text(
                      cover(namebuf), extract(object), false)};

                    entry_cio.print("${index}: ${attribute}=${value}")
                      .arg(EAGINE_ID(index), index)
                      .arg(EAGINE_ID(attribute), extract(name))
                      .arg(
                        EAGINE_ID(value), ssl.get_string_view(extract(value)));
                }
            }
        }

        file_contents cert_pem{cert_path};
        if(ok cert{ssl.parse_x509(cert_pem, {})}) {
            const auto del_cert{ssl.delete_x509.raii(cert)};

            if(ssl.ca_verify_certificate(ca_cert, cert)) {
                if(const auto subname{ssl.get_x509_subject_name(cert)}) {
                    const auto count{
                      extract(ssl.get_name_entry_count(extract(subname)))};
                    ctx.cio()
                      .print(
                        EAGINE_ID(ssl),
                        "successfully verified certificate ${certPath}")
                      .arg(EAGINE_ID(certPath), EAGINE_ID(FsPath), cert_path)
                      .arg(EAGINE_ID(snEntCount), count);
                    const auto entry_cio{
                      ctx.cio()
                        .print(
                          EAGINE_ID(ssl), "certificate common name entries:")
                        .to_be_continued()};

                    for(const auto index : integer_range(count)) {
                        if(const auto entry{
                             ssl.get_name_entry(extract(subname), index)}) {
                            const auto object{
                              ssl.get_name_entry_object(extract(entry))};
                            const auto value{
                              ssl.get_name_entry_data(extract(entry))};

                            std::array<char, 96> namebuf{};
                            const auto name{ssl.object_to_text(
                              cover(namebuf), extract(object), false)};

                            entry_cio.print("${index}: ${attribute}=${value}")
                              .arg(EAGINE_ID(index), index)
                              .arg(EAGINE_ID(attribute), extract(name))
                              .arg(
                                EAGINE_ID(value),
                                ssl.get_string_view(extract(value)));
                        }
                    }
                } else {
                    ctx.log()
                      .error(
                        "failed to get certificate ${certPath} serial number")
                      .arg(EAGINE_ID(certPath), EAGINE_ID(FsPath), cert_path);
                }
            } else {
                ctx.log()
                  .error("failed to verify certificate ${certPath}")
                  .arg(EAGINE_ID(certPath), EAGINE_ID(FsPath), cert_path);
            }
        } else {
            ctx.log()
              .error("failed to load certificate ${certPath}")
              .arg(EAGINE_ID(certPath), EAGINE_ID(FsPath), cert_path);
        }
    }

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine
