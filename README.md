# PAM Module for Authentication with PrivacyIDEA

## Build
This project requires the [very good JSON parser from nlohmann](https://github.com/nlohmann/json). Put the single include file `json.hpp` in `include`.

It also requires the following libraries: `libcurl4-openssl-dev`, `libssl-dev`, `libpam0g-dev`

Compile with:

    g++ -Wall -fPIC -g -Iinclude -c /path/to/src/pam_privacyidea.cpp -o obj/(Debug/Release)/src/pam_privacyidea.o
    g++ -Wall -fPIC -g -Iinclude -c /path/to/src/PrivacyIDEA.cpp -o obj/(Debug/Release)/src/PrivacyIDEA.o
    g++ -shared  obj/(Debug/Release)/src/pam_privacyidea.o obj/(Debug/Release)/src/PrivacyIDEA.o  -o bin/(Debug/Release)/pam_privacyidea.so -Wno-undef  -lcurl

## Configuration
The following values can be appended to the pam config file line that references this module:

* url=https://yourprivacyidea.com (REQUIRED!)
* nossl
* realm=yourRealm
* sendemptypass
* sendunixpass
* debug
* offlineFile=/path/to/your/file (default is /etc/privacyidea/pam.txt)
