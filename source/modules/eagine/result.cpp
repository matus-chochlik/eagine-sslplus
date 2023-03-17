/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
export module eagine.sslplus:result;
import eagine.core.types;
import eagine.core.memory;
import eagine.core.c_api;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export class ssl_no_result_info {
public:
    constexpr auto error_code(const anything) noexcept -> auto& {
        return *this;
    }

    constexpr auto message() const noexcept -> string_view {
        return {"OpenSSL function not available"};
    }

    constexpr auto set_unknown_error() noexcept -> auto& {
        return *this;
    }
};
//------------------------------------------------------------------------------
export class ssl_result_info {
public:
    constexpr ssl_result_info() noexcept = default;
    constexpr ssl_result_info(ssl_no_result_info) noexcept
      : _error_code{~0UL} {}

    explicit constexpr operator bool() const noexcept {
        return _error_code == 0;
    }

    constexpr auto error_code(const unsigned long ec) noexcept -> auto& {
        _error_code = ec;
        return *this;
    }

    constexpr auto set_unknown_error() noexcept -> auto& {
        if(not _error_code) {
            _error_code = ~0UL;
        }
        return *this;
    }

    auto message() const noexcept -> string_view {
        // TODO: get error string from OpenSSL
        return {"unknown ssl error"};
    }

private:
    unsigned long _error_code{0UL};
};
//------------------------------------------------------------------------------
export template <typename Result>
using ssl_no_result = c_api::no_result<Result, ssl_no_result_info>;
//------------------------------------------------------------------------------
export template <typename Result>
using ssl_result = c_api::result<Result, ssl_result_info>;
//------------------------------------------------------------------------------
export template <typename Result>
using ssl_opt_result = c_api::opt_result<Result, ssl_result_info>;
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

