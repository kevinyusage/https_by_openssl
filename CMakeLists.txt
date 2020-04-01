cmake_minimum_required(VERSION 3.12)
project(https_by_openssl)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 14)

set(SSL_REQUESTER
        SSLRequester.h
        SSLRequester.cpp)

set(OPENSSL_LIBS
        OpenSSL::SSL
        OpenSSL::Crypto)

add_executable(https_by_openssl main.cpp
        ${SSL_REQUESTER})

target_link_libraries(https_by_openssl ${OPENSSL_LIBS})
