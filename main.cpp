#include <iostream>
#include "SSLRequester.h"

int main() {
    std::cout << "Hello, World!" << std::endl;

    SSLRequester sslRequester;
    sslRequester.doSSLRequest();

    return 0;
}
