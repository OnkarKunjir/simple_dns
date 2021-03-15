cmake_minimum_required(VERSION 3.5)
project(simple_dns VERSION 0.0.1)

add_subdirectory(network)

add_executable(simple_dns main.cpp)
target_link_libraries(
  simple_dns PUBLIC
  Network
)

add_custom_target(
  test
  DEPENDS simple_dns
  COMMAND ./simple_dns < input.txt
)
