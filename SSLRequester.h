//
// Created by gackt on 4/1/20.
//

#ifndef HTTPS_BY_OPENSSL_SSLREQUESTER_H
#define HTTPS_BY_OPENSSL_SSLREQUESTER_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <fcntl.h>

/**
 * remove nonblock
 * @param fd
 * @return
 */
static int set_fd_nonblock(int fd) {
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK) == -1) {
        perror("set nonblock fail");
        return -1;
    }
    return 0;
}

class SSLRequester {

public:
    SSLRequester();

    virtual ~SSLRequester();

    void initIdBase64();

    void openConnection();

    void init_SSL_CTX();

    void initSSL();

    void doSSLRequest();

    void responseSSLRead();

    void showCerts();

private:

    char* hostname = "www3.ntu.edu.sg\0";
    //char* hostname = "cn.bing.com\0";
    uint16_t port = 443;

    int socketfd;
    struct hostent *host;
    struct sockaddr_in addrIn;

    SSL_CTX *sslCtx = nullptr;
    SSL *ssl = nullptr;

    std::string idBase64;

    // example header
    std::string getRequest = "GET /home/ehchua/programming/cpp/gcc_make.html HTTP/1.1\n"
                             "Host: www3.ntu.edu.sg\n"
                             "Connection: keep-alive\n"
                             "Cache-Control: max-age=0\n"
                             "Upgrade-Insecure-Requests: 1\n"
                             "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Safari/537.36\n"
                             "Sec-Fetch-Dest: document\n"
                             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\n"
                             "Sec-Fetch-Site: none\n"
                             "Sec-Fetch-Mode: navigate\n"
                             "Sec-Fetch-User: ?1\n"
                             "Accept-Encoding: gzip, deflate, br\n"
                             "Accept-Language: zh-CN,zh;q=0.9\r\n\r\n";

    std::string postHeader = "POST /home/ehchua/programming/cpp/gcc_make.html HTTP/1.1\n"
                             "Host: www3.ntu.edu.sg\n"
                             "Connection: keep-alive\n"
                             "Cache-Control: max-age=0\n"
                             "Upgrade-Insecure-Requests: 1\n"
                             "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Safari/537.36\n"
                             "Sec-Fetch-Dest: document\n"
                             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\n"
                             "Sec-Fetch-Site: none\n"
                             "Content-Length: 25\r\n\r\n"
                             "This is the request body.";
};

#endif //HTTPS_BY_OPENSSL_SSLREQUESTER_H
