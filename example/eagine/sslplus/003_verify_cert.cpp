/// @example eagine/sslplus/003_verify_cert.cpp
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#include <eagine/file_contents.hpp>
#include <eagine/logging/logger.hpp>
#include <eagine/main.hpp>
#include <eagine/sslplus/openssl.hpp>

#include <eagine/sslplus/api.hpp>

#include <array>

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {

    string_view ca_cert_path{"example-ca.crt"};
    if(const auto arg{ctx.args().find("--ca-cert").next()}) {
        ca_cert_path = arg;
    }

    string_view cert_path{"example.crt"};
    if(const auto arg{ctx.args().find("--cert").next()}) {
        cert_path = arg;
    }
    file_contents cert_pem{cert_path};

    const sslplus::ssl_api ssl;

    if(ok cert{ssl.parse_x509(cert_pem, {})}) {
        const auto del_cert{ssl.delete_x509.raii(cert)};

        if(ssl.ca_verify_certificate(ca_cert_path, cert)) {
            if(ssl.certificate_subject_name_has_entry_value(
                 cert, "organizationName", "OGLplus.org")) {
                if(const auto serial{ssl.get_x509_serial_number(cert)}) {
                    ctx.log()
                      .info("successfully verified certificate ${certPath}")
                      .arg(EAGINE_ID(certPath), EAGINE_ID(FsPath), cert_path)
                      .arg(
                        EAGINE_ID(serialNo),
                        extract(ssl.get_int64(extract(serial))));
                } else {
                    ctx.log()
                      .error(
                        "failed to get certificate ${certPath} serial number")
                      .arg(EAGINE_ID(certPath), EAGINE_ID(FsPath), cert_path);
                }
            } else {
                ctx.log()
                  .error("certificate does not have required value")
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

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine
