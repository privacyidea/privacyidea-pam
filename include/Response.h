#ifndef RESPONSE_H
#define RESPONSE_H

#include <string>

struct Response
{
    // In case of a challenge, these will be set
    std::string message;
    std::string transactionID;

    bool pushTriggered = false;

    // Indicate whether the user should be prompted for an input
    bool promptForOTP = false;

    std::string errorMessage;
    int errorCode;

    bool authenticationSuccess;
};

#endif // RESPONSE_H
