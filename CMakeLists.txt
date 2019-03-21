cmake_minimum_required(VERSION 3.10)
project(oc-memtest)

set(CMAKE_CXX_STANDARD 17)

string(REPLACE "/MDd" "/MTd" CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_CXX_FLAGS_DEBUG}")
string(REPLACE "/MD"  "/MT"  CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

add_executable(oc-memtest main.cpp)
