/// @example eagine/sslplus/002_hash_self.cpp
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#if EAGINE_SSLPLUS_MODULE
import eagine.core;
import eagine.sslplus;
import <array>;
#else
#include <eagine/console/console.hpp>
#include <eagine/file_contents.hpp>
#include <eagine/logging/logger.hpp>
#include <eagine/main_ctx.hpp>
#include <eagine/sslplus/openssl.hpp>

#include <eagine/sslplus/api.hpp>
#include <array>
#endif

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {
    file_contents data(ctx.exe_path());
    std::array<byte, 32> temp{};

    const sslplus::ssl_api ssl;

    if(memory::const_block hash{ssl.sha256_digest(data, cover(temp))}) {
        ctx.cio().print(identifier{"sslplus"}, "data hashed successfully");
        ctx.log().info("hash of self").arg(identifier{"hash"}, hash);
    }

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine

auto main(int argc, const char** argv) -> int {
    return eagine::default_main(argc, argv, eagine::main);
}

