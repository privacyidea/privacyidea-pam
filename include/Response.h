#ifndef RESPONSE_H
#define RESPONSE_H

#include <string>

struct Response
{
    // In case of a challenge, these will be set
    std::string message;
    std::string transactionID;
    // optional
    bool pushTriggered = false;

    std::string errorMessage;
    int errorCode;

    bool authenticationSuccess;
};

#endif // RESPONSE_H
