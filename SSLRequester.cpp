//
// Created by gackt on 4/1/20.
//

#include "SSLRequester.h"

SSLRequester::SSLRequester() {
    // Init ssl library
    SSL_library_init();

    // Init base64-id
    initIdBase64();

    init_SSL_CTX();

    openConnection();

    initSSL();
}

SSLRequester::~SSLRequester() {
    if (ssl != nullptr) {
        SSL_free(ssl); // close SSL connect
    }

    if (socketfd != -1) {
        close(socketfd);  // close socket
    }

    if (sslCtx != nullptr) {
        SSL_CTX_free(sslCtx); // release context
    }
}

void SSLRequester::initIdBase64() {
    // example
    std::string rawid = "123456abcdef";
    // read whole file
    if (std::ifstream is{rawid, std::ios::binary | std::ios::ate}) {
        auto size = is.tellg();
        std::string str(size, '\0');  // construct string to stream size
        is.seekg(0, std::ios::beg);
        if (is.read(&str[0], size)) {
            BIO *bmem = nullptr;
            BIO *b64 = nullptr;
            BUF_MEM *bptr = nullptr;


            // Base64 encode method
            b64 = BIO_new(BIO_f_base64()); // no-newline encode for make post-req
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            bmem = BIO_new(BIO_s_mem());
            b64 = BIO_push(b64, bmem);

            BIO_write(b64, str.data(), str.length());

            BIO_flush(b64);
            BIO_get_mem_ptr(b64, &bptr);

            std::string tmpBase64(bptr->data, bptr->length);
            idBase64 = tmpBase64;

            // One time read and encode
            BIO_free_all(b64);
        }
    }
}

void SSLRequester::openConnection() {
    if ((host = gethostbyname(hostname)) == nullptr) {
        exit(-1);
    }
    socketfd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addrIn, sizeof(addrIn));
    addrIn.sin_family = AF_INET;
    addrIn.sin_port = htons(port);
    addrIn.sin_addr.s_addr = *reinterpret_cast<int64_t *>(host->h_addr);

    if (connect(socketfd, (struct sockaddr*) &addrIn, sizeof(addrIn)) != 0) {
        close(socketfd);
        exit(-1);
    }

    // set_fd_nonblock(socketfd);
}

void SSLRequester::init_SSL_CTX(){
    OpenSSL_add_all_algorithms();  // load cryptos
    SSL_load_error_strings();  // Bring in and register error messages;
    //const SSL_METHOD *method = SSLv23_method();  // Create new client-method instance
    const SSL_METHOD *method = SSLv23_method();  // Create new client-method instance
    sslCtx = SSL_CTX_new(method);  // Create new context
    if (sslCtx == nullptr) {
        ERR_print_errors_fp(stderr);
    }
}

void SSLRequester::initSSL() {
    ssl = SSL_new(sslCtx);  // create new SSL connection state
    SSL_set_fd(ssl, socketfd);  // attach the socket descriptor
    if (SSL_connect(ssl) == -1) {  // perform the connection
        ERR_print_errors_fp(stderr);
    } else {
        showCerts();  // debug print certs;
    }
}

void SSLRequester::showCerts() {
    X509 *cert = nullptr;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != nullptr) {
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf(line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf(line);
        free(line);
        X509_free(cert);
    }
}

void SSLRequester::doSSLRequest() {
    auto ret = SSL_write(ssl, getRequest.data(), getRequest.length());
    auto error = SSL_get_error(ssl, ret);
    if (error != SSL_ERROR_NONE) {
        printf("SSL_write error %d \n", error);
    }
    // read response
    responseSSLRead();
}

void SSLRequester::responseSSLRead() {
    std::string respBody;
    do {
        char buf[8192];
        auto len = SSL_read(ssl, buf, 8192);
        respBody.append(buf, len);
    } while (respBody.find("</html>") == std::string::npos);
    // print
    std::cout << respBody << std::endl;
}
