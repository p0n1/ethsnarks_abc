cmake_minimum_required(VERSION 2.8)
project(ethsnarks_abc)
add_subdirectory(../../ethsnarks ../../.build/ethsnarks EXCLUDE_FROM_ALL)

if (CMAKE_VERSION VERSION_GREATER "3.0")
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED ON) #...is required...
else()
  include(CheckCXXCompilerFlag)
  CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)

  if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  elseif(COMPILER_SUPPORTS_CXX0X)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
  else()
        message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
  endif()
endif()

add_executable(poseidon poseidon.cpp)
target_link_libraries(poseidon ethsnarks_common crypto)