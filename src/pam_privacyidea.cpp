#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <stdbool.h>
#include <iostream>
#include "PrivacyIDEA.h"
#include "Config.h"
#include <syslog.h>
#include "Response.h"

using namespace std;

static int pam_prompt(pam_handle_t *pamh, int msg_style, const char *prompt, std::string &response)
{
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    int retval;

    if (pam_get_item(pamh, PAM_CONV, (const void **) &conv) != PAM_SUCCESS || !conv || !conv->conv)
    {
        return PAM_SYSTEM_ERR;
    }

    msg.msg_style = msg_style;
    msg.msg = prompt;
    msgp = &msg;

    retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);

    if (retval == PAM_SUCCESS && resp)
    {
        if (!*resp->resp)
        {
            retval = PAM_CONV_ERR;
        }
        response = string(resp->resp);
        free(resp);
    }

    return retval;
}

void getConfig(int argc, const char **argv, Config &config)
{
    for (int i = 0; i < argc; i++)
    {
        char *pArg;
        memcpy(&pArg, &argv[i], sizeof(pArg));
        string tmp(pArg);
        //printf("Arugment: %s\n", tmp.c_str());

        if (tmp.rfind("url=", 0) == 0)
        {
            config.url = tmp.substr(4);
        }
        else if (tmp == "debug")
        {
            config.debug = true;
        }
        else if (tmp == "nossl")
        {
            config.disableSSLVerify = true;
        }
        else if (tmp == "sendemptypass")
        {
            config.sendEmptyPass = true;
        }
        else if (tmp == "sendunixpass")
        {
            config.sendUnixPass = true;
        }
        else if (tmp.rfind("realm=", 0) == 0)
        {
            config.realm = tmp.substr(6);
        }
        else if (tmp.rfind("offlineFile=", 0) == 0)
        {
            config.offlineFile = tmp.substr(12);
        }
        else if (tmp.rfind("prompt=", 0) == 0)
        {
            config.promptText = tmp.substr(7);
        }
    }
}

extern "C" {
    PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    openlog("pam_privacyidea", LOG_PID | LOG_CONS, LOG_AUTH);
    // Get arguments, url is required
    if (argc == 0 || argv == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "No url specified!");
        return PAM_SERVICE_ERR;
    }

    Config config;
    getConfig(argc, argv, config);
    PrivacyIDEA privacyidea(pamh, config.url, !config.disableSSLVerify, config.offlineFile);

    // Username
    int retval = PAM_SUCCESS;
    const char *pUsername;
    retval = pam_get_user(pamh, &pUsername, "Username: ");
    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to get username! Error: %d\n", retval);
        return retval;
    }
    string username(pUsername);

    // Password
    const char *authtok = NULL; // Do not free/overwrite where this points to
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL);
    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to retrieve authtok with error %d\n", retval);
        return PAM_SERVICE_ERR;
    }
    string password(authtok);

    // Setup some data required for requests
    retval = 0;
    Response oldResponse;

    // If enabled, do either sendUnixPass or sendEmptyPass
    if (config.sendUnixPass)
    {
        retval = privacyidea.validateCheck(username, password, "", oldResponse);
    }
    else if (config.sendEmptyPass)
    {
        retval = privacyidea.validateCheck(username, "", "", oldResponse);
    }

    if (retval != 0)
    {
        // Do not abort in this case, offline authentication is still be possible
        // TODO remove the log as it is expected in some cases?
        pam_syslog(pamh, LOG_ERR, "Unable to send request to the privacyIDEA server. Error %d\n", retval);
        // return PAM_AUTH_ERR;
    }

    // Check if authentication has already succeeded because of passOnNoToken or passOnNoUser
    if (oldResponse.authenticationSuccess) {
        printf("%s", oldResponse.message.c_str());
        return PAM_SUCCESS;
    }

    // Setup for the OTP step, possibly with the response of sendUnixPass or sendEmptyPass
    string prompt = config.promptText.empty() ? "Please enter your OTP:" : config.promptText;

    // LOOP: Repeat prompt for user input until privacyIDEA responds with authentication success
    bool success = false;
    while (true)
    {
        // Get the OTP/input with message from previous response or from config
        Response newResponse;
        if (!oldResponse.message.empty())
        {
            prompt = oldResponse.message;
        }
        string otp;
        retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, prompt.c_str(), otp);

        // OFFLINE check if data is present, try offline and refill if needed
        string serialUsed;
        retval = privacyidea.offlineCheck(username, otp, serialUsed);
        printf("Offline retval: %d\n", retval);
        if (retval == OFFLINE_SUCCESS)
        {
            success = true;
            // it is possible that refill "fails" because the machine is offine
            privacyidea.offlineRefill(username, otp, serialUsed);
            break;
        }

        // POLL: If push was triggered before, try polling and finalizing
        bool pushFinalizing = false;
        if (oldResponse.pushTriggered)
        {
            printf("Push triggered, polling for transaction..\n");
            if (privacyidea.pollTransaction(oldResponse.transactionID))
            {
                printf("Transaction succeeded, finalizing\n");
                // Finalize with request to /validate/check and empty pass
                retval = privacyidea.validateCheck(username, "", oldResponse.transactionID, newResponse);
                pushFinalizing = true;
            }
        }

        // OTP: Send the input
        if (!pushFinalizing)
        {
            retval = privacyidea.validateCheck(username, otp, oldResponse.transactionID, newResponse);
        }
        if (retval != 0)
        {
            // TODO break?
        }

        // Check the response for error and authentication success. If challenges were triggered, just do the next iteration of the loop
        if (!newResponse.errorMessage.empty())
        {
            pam_syslog(pamh, LOG_ERR, "Unable to authenticate with privacyIDEA: %s (Code: %d)\n", newResponse.errorMessage.c_str(),
                       newResponse.errorCode);
            break;
        }
        else if (newResponse.transactionID.empty())
        {
            success = newResponse.authenticationSuccess;
            printf("Authentication end with success=%s\n", success ? "true" : "false");
            break;
        }

        oldResponse = newResponse;
    } // End loop

    closelog();
    return success ? PAM_SUCCESS : PAM_AUTH_ERR;
}

