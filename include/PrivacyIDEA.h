#ifndef PAM_PRIVACYIDEA_PRIVACYIDEA_H
#define PAM_PRIVACYIDEA_PRIVACYIDEA_H

#include <string>
#include <map>
#include <security/pam_ext.h>
#include "response.h"
#include "json.hpp"

#define PAM_PRIVACYIDEA_USERAGENT           "privacyidea-pam/1.0.0"

#define OFFLINE_SUCCESS                     0
#define OFFLINE_FAIL                        1
#define OFFLINE_FILE_MISSING                2
#define OFFLINE_FILE_ACCESS_FAIL            3
#define OFFLINE_FILE_PARSE_FAIL             4
#define OFFLINE_FILE_WRONG_FORMAT           5
#define OFFLINE_USER_NOT_FOUND              6
#define OFFLINE_NO_DATA                     10
#define OFFLINE_NO_OTPS_LEFT                11

class PrivacyIDEA
{
public:
    PrivacyIDEA(pam_handle_t* pamh, std::string baseURL, bool sslVerify, std::string offlineFile, bool debug);

    ~PrivacyIDEA();

    bool pollTransaction(const std::string &transactionID);

    int validateCheck(const std::string &user, const std::string &pass, const std::string &transactionID, Response &response);

    int sendRequest(const std::string &url, const std::map<std::string, std::string> &parameters, const std::map<std::string, std::string> &headers,
                    std::string& response, bool postRequest = true);

    int parseResponse(const std::string &input, Response &out);

    int offlineCheck(const std::string &user, const std::string &otp, std::string& serialUsed);

    int offlineRefill(const std::string& user, const std::string& lastOTP, const std::string& serial);

private:
    pam_handle_t* pamh; // for syslog
    bool debug = false;

    std::string baseURL;
    bool sslVerify;

    std::string offlineFile = "/etc/privacyidea/pam.txt";
    nlohmann::json offlineData;

    bool pbkdf2_sha512_verify(const std::string &password, std::string comparable);

    std::string base64Encode(const unsigned char* data, size_t length);

    std::vector<unsigned char> base64Decode(const std::string& encoded_string);
    // Returns the outer right value of the passlib format and cuts it off the input string including the $
    std::string getNextValue(std::string& in);

    std::string readAll(std::string file);

    void writeAll(std::string file, std::string content);
};

#endif //PAM_PRIVACYIDEA_PRIVACYIDEA_H
