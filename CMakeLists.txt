# Copyright Matus Chochlik.
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at
#  http://www.boost.org/LICENSE_1_0.txt
#
cmake_minimum_required(VERSION 3.10)

project(EAGineSSL)
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/config)
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/submodules/eagine-core/config)

find_package(EAGineOpenSSL REQUIRED)

add_subdirectory(submodules)

include(EAGineCoreCommon)

add_subdirectory(include)
add_subdirectory(source)
add_subdirectory(example)
