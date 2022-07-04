/// @example eagine/sslplus/001_list_engines.cpp
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
#include <eagine/main_ctx.hpp>
#include <eagine/main_ctx_object.hpp>
#include <eagine/sslplus/openssl.hpp>

#include <eagine/sslplus/api.hpp>
#include <array>
#endif

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {

    const sslplus::ssl_api ssl;
    main_ctx_object out{identifier{"ssl"}, ctx};

    ssl.load_builtin_engines();

    const auto engines_cio{out.cio_print("SSL engines").to_be_continued()};

    const auto func = [&](sslplus::engine eng) {
        const string_view na("N/A");
        engines_cio.print("engine ${id}: '${name}'")
          .arg(identifier{"id"}, extract_or(ssl.get_engine_id(eng), na))
          .arg(identifier{"name"}, extract_or(ssl.get_engine_name(eng), na));
    };

    ssl.for_each_engine(func);

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine

auto main(int argc, const char** argv) -> int {
    return eagine::default_main(argc, argv, eagine::main);
}

