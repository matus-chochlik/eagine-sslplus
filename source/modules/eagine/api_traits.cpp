/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
export module eagine.sslplus:api_traits;
import eagine.core.c_api;
import :result;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export class ssl_api_traits : public c_api::default_traits {
public:
    template <typename R>
    using no_result = ssl_no_result<R>;
    template <typename R>
    using result = ssl_result<R>;
    template <typename R>
    using opt_result = ssl_opt_result<R>;

    template <typename Result>
    using combined_result = c_api::combined_result<Result, ssl_result_info>;

private:
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

