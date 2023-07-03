#include "PrivacyIDEA.h"
#include <curl/curl.h>
#include <cstring>
#include <errno.h>
#include <sstream>
#include <iomanip>
#include <syslog.h>
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;
using json = nlohmann::json;

PrivacyIDEA::PrivacyIDEA(pam_handle_t* pamh, std::string baseURL, bool sslVerify, std::string offlineFile, bool debug)
{
    this->pamh = pamh;
    this->baseURL = baseURL;
    this->sslVerify = sslVerify;
    this->debug = debug;
    if (!offlineFile.empty())
    {
        this->offlineFile = offlineFile;
    }

    string content = readAll(offlineFile);
    if (!content.empty())
    {
        try
        {
            offlineData = json::parse(content);
        }
        catch (const json::parse_error &e)
        {
            // TODO keep this debug, because having the file is not required
            pam_syslog(pamh, LOG_DEBUG, "Unable to load offline data: %s", e.what());
        }
    }
}

PrivacyIDEA::~PrivacyIDEA()
{
    if (!offlineData.empty())
    {
        writeAll(offlineFile, offlineData.dump(4));
    }
}

std::string urlEncode(const std::string &input)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto c: input)
    {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
        }
        // Any other characters are percent-encoded
        else
        {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char) c);
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}

size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((string *) userp)->append((char *) contents, size * nmemb);
    return size * nmemb;
}

bool PrivacyIDEA::pollTransaction(const string &transactionID)
{
    int retval = 0;
    string strResponse;
    map <string, string> param
    {
        make_pair("transaction_id", transactionID)
    };
    map <string, string> headers;

    retval = sendRequest(baseURL + "/validate/polltransaction", param, headers, strResponse, false);
    if (retval != 0)
    {
        return false;
    }

    Response response;
    retval = parseResponse(strResponse, response);
    if (retval != 0)
    {
        return false;
    }
    return response.authenticationSuccess;
}

int PrivacyIDEA::validateCheck(const string &user, const string &pass, const string &transactionID,
                               Response &response)
{
    int retval = 0;
    string strResponse;
    map <string, string> param
    {
        make_pair("user", user),
        make_pair("pass", pass)
    };
    if (!transactionID.empty())
    {
        param.emplace("transaction_id", transactionID);
    }

    map <string, string> headers;

    retval = sendRequest(baseURL + "/validate/check", param, headers, strResponse);
    if (retval != 0)
    {
        // Do not abort in this case, offline authentication is still be possible
        // TODO remove the log as it is expected in some cases?
        pam_syslog(pamh, LOG_ERR, "Unable to send request to the privacyIDEA server. Error %d\n", retval);
        // return PAM_AUTH_ERR;
    }
    retval = parseResponse(strResponse, response);
    if (retval != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to parse the response from the privacyIDEA server. Response: %s\n Error %d\n",
                   strResponse.c_str(), retval);
        // return PAM_AUTH_ERR;
    }
    return retval;
}

int PrivacyIDEA::sendRequest(const std::string &url, const std::map <std::string, std::string> &parameters,
                             const std::map <std::string, std::string> &headers,
                             std::string &response, bool postRequest)
{
    CURL *curl;
    CURLcode res = CURLE_OK;
    string readBuffer;

    curl = curl_easy_init();
    if (curl)
    {
        string postData;
        for (const auto &param: parameters)
        {
            postData += param.first + "=" + urlEncode(param.second) + "&";
        }
        postData = postData.substr(0, postData.length() - 1); // Remove the trailing '&'

        if (debug)
        {
            pam_syslog(pamh, LOG_DEBUG, "Sending %s to %s", postData.c_str(), url.c_str());
        }


        if (postRequest)
        {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        }
        else
        {
            // GET request
            curl_easy_setopt(curl, CURLOPT_URL, (url + "?" + postData).c_str());
        }

        struct curl_slist *headers_list = nullptr;
        for (const auto &header: headers)
        {
            string headerString = header.first + ": " + header.second;
            headers_list = curl_slist_append(headers_list, headerString.c_str());
        }
        headers_list = curl_slist_append(headers_list, ("User-Agent: " + string(HTTP_USER_AGENT)).c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);

        if (!sslVerify)
        {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
        }

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);

        curl_slist_free_all(headers_list);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK)
        {
            response = readBuffer;
        }
    }
    else
    {
        res = CURLE_FAILED_INIT;
    }

    return (int) res;
}

int PrivacyIDEA::offlineRefill(const std::string& user, const std::string& lastOTP, const std::string& serial)
{
    if (debug)
    {
        pam_syslog(pamh, LOG_DEBUG, "Attempting offline refill for user %s with token %s", user.c_str(), serial.c_str());
    }

    if (!offlineData.contains("offline") || !offlineData["offline"].is_array())
    {
        return OFFLINE_FILE_WRONG_FORMAT;
    }

    for (auto& item: offlineData["offline"])
    {
        if (item.contains("serial") && item["serial"].get<std::string>() == serial)
        {
            map<string, string> parameters =
            {
                {"pass", lastOTP},
                {"refilltoken", item["refilltoken"].get<std::string>()},
                {"serial", serial}
            };
            map<string,string> headers;
            string response;
            auto retval = sendRequest(baseURL + "/validate/offlinerefill", parameters, headers, response);

            if (retval != 0)
            {
                // TODO might be expected when the machine is offline, leave it at debug
                if (debug)
                {
                    pam_syslog(pamh, LOG_DEBUG, "%s", "Unable to refill offline values");
                }
                break;
            }

            json j;
            try
            {
                j = json::parse(response);
            }
            catch (const json::parse_error &e)
            {
                pam_syslog(pamh, LOG_ERR, "Unable parse refill response!");
                return 1;
            }

            if (j.contains("auth_items") && j["auth_items"].contains("offline") && j["auth_items"]["offline"].is_array() && j["auth_items"]["offline"].size() > 0
                    && j["auth_items"]["offline"][0].contains("refilltoken") && j["auth_items"]["offline"][0].contains("response"))
            {
                item["refilltoken"] = j["auth_items"]["offline"][0]["refilltoken"];
                item["response"].update(j["auth_items"]["offline"][0]["response"]);
                if (debug)
                {
                    pam_syslog(pamh, LOG_DEBUG, "Offline refill completed. New item:%s\n", item.dump(4).c_str());
                }

            }
            else
            {
                pam_syslog(pamh, LOG_ERR, "Unable to update offline data because refill response is malformed:\n%s", j.dump(4).c_str());
            }
        }
    }
    return 0;
}

int PrivacyIDEA::offlineCheck(const std::string &user, const std::string &otp, std::string& serialUsed)
{
    // Check if given user exists
    if (!offlineData.contains("offline") || !offlineData["offline"].is_array())
    {
        return OFFLINE_FILE_WRONG_FORMAT;
    }

    bool userFound = false;
    bool success = false;

    for (auto& item: offlineData["offline"])
    {
        if (item.contains("username") && item["username"].get<string>() == user)
        {
            userFound = true;
            if (debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "Offline token with serial %s found for user %s", item["serial"].get<std::string>().c_str(), user.c_str());
            }

            if (item.contains("response"))
            {
                // Order the string keys in the map by their numeric value
                auto comp = [](const string& a, const string& b)
                {
                    return stoi(a) < stoi(b);
                };
                map <string, string, decltype(comp)> offlineMap(comp);
                for (auto& offlineEntries: item["response"].items())
                {
                    offlineMap.emplace(offlineEntries.key(), offlineEntries.value());
                }

                int lowestKey = stoi(offlineMap.begin()->first);
                int matchingKey = 0;
                int window = 10; // TODO make this configurable?
                for (auto& offlineEntries: offlineMap)
                {
                    int index = stoi(offlineEntries.first);
                    if (index >= (lowestKey + window))
                    {
                        break;
                    }

                    if(pbkdf2_sha512_verify(otp, offlineEntries.second))
                    {
                        matchingKey = index;
                        success = true;
                        serialUsed = item["serial"].get<std::string>();
                        if (debug)
                        {
                            pam_syslog(pamh, LOG_DEBUG, "Success.");
                        }
                        break;
                    }
                }

                if (success)
                {
                    // remove the "used" values
                    for (int i = lowestKey; i <= matchingKey; i++)
                    {
                        item["response"].erase(to_string(i));
                    }
                    break;
                }
            }
        }
    }

    return userFound ? (success ? OFFLINE_SUCCESS : OFFLINE_FAIL) : OFFLINE_USER_NOT_FOUND;
}

// Returns the outer right value of the passlib format and cuts it off the input string including the $
std::string PrivacyIDEA::getNextValue(std::string& in)
{
    string tmp = in.substr(in.find_last_of('$') + 1);
    in = in.substr(0, in.find_last_of('$'));
    return tmp;
}

std::string PrivacyIDEA::base64Encode(const unsigned char* data, size_t length)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded_string;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (length--)
    {
        char_array_3[i++] = *(data++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                encoded_string += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            encoded_string += base64_chars[char_array_4[j]];

        //while (i++ < 3)
        //  encoded_string += '=';
    }

    return encoded_string;
}

std::vector<unsigned char> PrivacyIDEA::base64Decode(const std::string& encoded_string)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::vector<unsigned char> decoded_data;
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/')))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                decoded_data.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++)
            decoded_data.push_back(char_array_3[j]);
    }

    return decoded_data;
}

bool PrivacyIDEA::pbkdf2_sha512_verify(const std::string &password, std::string comparable)
{
    // Format of stored values (passlib):
    // $algorithm$iteratons$salt$checksum
    string storedOTP = getNextValue(comparable);
    // $algorithm$iteratons$salt
    string saltStr = getNextValue(comparable);
    // $algorithm$iteratons
    int iterations = 10000;

    try
    {
        iterations = stoi(getNextValue(comparable));
    }
    catch (const invalid_argument& e)
    {

    }
    // $algorithm
    string algorithm = getNextValue(comparable);

    // Salt and OTP are in adapted abase64 encoding of passlib where [./+] is substituted
    std::replace(saltStr.begin(), saltStr.end(), '.', '+');
    std::replace(storedOTP.begin(), storedOTP.end(), '.', '+');
    auto salt = base64Decode(saltStr);

    const int derivedKeyLength = 64; // SHA-512 produces 64-byte hash
    unsigned char derivedKey[derivedKeyLength];
    int result = PKCS5_PBKDF2_HMAC(
                     password.c_str(),
                     password.length(),
                     salt.data(),
                     salt.size(),
                     iterations,
                     EVP_sha512(),
                     derivedKeyLength,
                     derivedKey
                 );

    if (result != 1)
    {
        printf("Error occurred while deriving key %d\n", result);
        return false;
    }

    string enc = base64Encode(derivedKey, derivedKeyLength);
    return enc == storedOTP;
}

std::string PrivacyIDEA::readAll(std::string file)
{
    std::ifstream inFile(offlineFile);
    if (!inFile)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to open offline file. Error: %d %s", errno, strerror(errno));
    }
    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    return content;
}

void PrivacyIDEA::writeAll(std::string file, std::string content)
{
    std::ofstream outFile(file, std::ios::trunc);
    if (!outFile)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to open offline file. Error: %d %s", errno, strerror(errno));
        // TODO do not return error here?
    }

    outFile << content;
    outFile.close();
}

int PrivacyIDEA::parseResponse(const std::string &input, Response &out)
{
    if (debug)
    {
        pam_syslog(pamh, LOG_DEBUG, "%s", input.c_str());
    }
    json jResponse;
    try
    {
        jResponse = json::parse(input);
    }
    catch (const json::parse_error &e)
    {
        return 1;
    }

    if (jResponse.contains("result") && jResponse["result"].contains("value"))
    {
        out.authenticationSuccess = jResponse["result"]["value"].get<bool>();
    }

    if (jResponse.contains("result") && jResponse["result"].contains("error"))
    {
        out.errorMessage = jResponse["result"]["error"]["message"].get<std::string>();
        out.errorCode = jResponse["result"]["error"]["code"].get<int>();
    }

    if (jResponse.contains("detail"))
    {
        if (jResponse["detail"].contains("message"))
        {
            out.message = jResponse["detail"]["message"].get<std::string>();
        }

        if (jResponse["detail"].contains("transaction_id"))
        {
            out.transactionID = jResponse["detail"]["transaction_id"].get<std::string>();
        }

        if (jResponse["detail"].contains("multi_challenge") && jResponse["detail"]["multi_challenge"].is_array() && jResponse["detail"]["multi_challenge"].size() > 0)
        {
            for (auto &item: jResponse["detail"]["multi_challenge"].items())
            {
                if (item.value()["type"] == "push")
                {
                    out.pushTriggered = true;
                }
                else
                {
                    out.promptForOTP = true;
                }
            }
        }
    }

    // If no push token was triggered, or there simply was no challenge, set promptForOTP to true
    if (!out.pushTriggered)
    {
        out.promptForOTP = true;
    }

    // Check if offline OTPs have been sent for the token used
    if (jResponse.contains("auth_items"))
    {
        for (auto item: jResponse["auth_items"]["offline"])
        {
            offlineData["offline"].push_back(item);
            if (debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "Added offline data for user %s with serial %s\n", item["username"].get<string>().c_str(), item["serial"].get<string>().c_str());
            }

        }
    }

    return 0;
}
