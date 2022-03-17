/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_API_TRAITS_HPP
#define EAGINE_SSLPLUS_API_API_TRAITS_HPP

#include "result.hpp"
#include <eagine/c_api/api_traits.hpp>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
class ssl_api_traits : public c_api::default_traits {
public:
    template <typename R>
    using no_result = ssl_no_result<R>;
    template <typename R>
    using result = ssl_result<R>;
    template <typename R>
    using opt_result = ssl_opt_result<R>;

    template <typename Result>
    using combined_result = c_api::combined_result<Result, ssl_result_info>;

    template <typename Api, typename Result>
    static constexpr auto check_result(Api& api, Result res) noexcept {
        res.error_code(api.err_get_error());
        return res;
    }

private:
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif // EAGINE_SSLPLUS_API_API_TRAITS_HPP
