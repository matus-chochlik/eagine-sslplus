/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
export module eagine.sslplus:api_traits;
import eagine.core.memory;
import eagine.core.c_api;
import :result;
import std;

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

    template <typename Api, typename Tag, typename Signature>
    auto link_function(
      Api&,
      const Tag,
      const string_view name,
      const std::type_identity<Signature>) -> std::add_pointer_t<Signature> {
        return reinterpret_cast<std::add_pointer_t<Signature>>(
          _link_function(name));
    }

private:
    using _any_fnptr_t = void (*)();

    auto _link_function(const string_view) -> _any_fnptr_t;
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

