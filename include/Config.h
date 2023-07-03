#ifndef PRIVACYIDEA_PAM_CONFIG_H
#define PRIVACYIDEA_PAM_CONFIG_H

#include <string>

struct Config
{
    std::string url;
    bool disableSSLVerify = false;
    bool debug = false;
    bool sendEmptyPass = false;
    bool sendUnixPass = false;
    std::string realm;
    std::string promptText;
    std::string offlineFile;
    int pollTimeInSeconds = 0; // 0 is default and means poll once
};

#endif //PRIVACYIDEA_PAM_CONFIG_H
