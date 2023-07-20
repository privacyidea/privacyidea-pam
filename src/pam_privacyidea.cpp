#include <thread>
#include <chrono>
#include <iostream>
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
#include <syslog.h>
#include "privacyIDEA.h"
#include "config.h"
#include "response.h"

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
        else
        {
            response = string(resp->resp);
        }

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
        else if (tmp == "sendEmptyPass")
        {
            config.sendEmptyPass = true;
        }
        else if (tmp == "sendPassword")
        {
            config.sendPassword = true;
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
        else if (tmp.rfind("pollTime=", 0) == 0)
        {
            config.pollTimeInSeconds = atoi(tmp.substr(9,11).c_str());
        }
    }
}

extern "C"
{
    PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);


    PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

} // extern "C"

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
    PrivacyIDEA privacyidea(pamh, config.url, !config.disableSSLVerify, config.offlineFile, config.debug);

    // Username
    int retval = PAM_SUCCESS;
    const char *pUsername;
    retval = pam_get_user(pamh, &pUsername, "Username: ");
    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to get username! Error: %d", retval);
        return retval;
    }
    string username(pUsername);

    // Setup some data required for requests
    retval = 0;
    Response oldResponse;

    // If enabled, do either sendPassword or sendEmptyPass
    if (config.sendPassword)
    {
        const char *authtok = NULL; // Do not free/overwrite where this points to
        retval = pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL);
        if (retval != PAM_SUCCESS)
        {
            pam_syslog(pamh, LOG_ERR, "Unable to retrieve authtok with error %d", retval);
            return PAM_SERVICE_ERR;
        }
        string password(authtok);
        retval = privacyidea.validateCheck(username, password, "", oldResponse);
    }
    else if (config.sendEmptyPass)
    {
        retval = privacyidea.validateCheck(username, "", "", oldResponse);
    }
    else
    {
        // If nothing is sent, set this so that the user is prompted for input
        oldResponse.promptForOTP = true;
    }

    if (retval != 0)
    {
        // Do not abort in this case, offline authentication is still be possible
        // TODO remove the log as it is expected in some cases?
        pam_syslog(pamh, LOG_ERR, "Unable to send request to the privacyIDEA server. Error %d\n", retval);
        // return PAM_AUTH_ERR;
    }

    // Check if authentication has already succeeded because of passOnNoToken or passOnNoUser
    if (oldResponse.authenticationSuccess)
    {
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

        // Prompt only if indicated by last response
        string otp;
        if (oldResponse.promptForOTP)
        {
            retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, prompt.c_str(), otp);
            if (retval != 0)
            {
                pam_syslog(pamh, LOG_ERR, "PAM conv error: %d", retval);
            }
            // OFFLINE check if data is present, try offline and refill if needed
            string serialUsed;
            retval = privacyidea.offlineCheck(username, otp, serialUsed);
            if (config.debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "Offline retval: %d", retval);
            }

            if (retval == OFFLINE_SUCCESS)
            {
                success = true;
                // it is possible that refill "fails" because the machine is offine
                privacyidea.offlineRefill(username, otp, serialUsed);
                break;
            }
        }

        // POLL: If push was triggered before, try polling and finalizing
        bool pushFinalizing = false;
        if (oldResponse.pushTriggered)
        {
            // Poll twice per second, but only poll for the given time if no OTP is requested from the user
            // If the user could also enter an OTP, only poll once because the execution has been blocked before by the prompt
            int pollCount = (config.pollTimeInSeconds == 0 || oldResponse.promptForOTP) ? 0 : (config.pollTimeInSeconds * 2);
            do
            {
                std::chrono::milliseconds duration(500);
                std::this_thread::sleep_for(duration);
                if (privacyidea.pollTransaction(oldResponse.transactionID))
                {
                    // Finalize with request to /validate/check and empty pass
                    retval = privacyidea.validateCheck(username, "", oldResponse.transactionID, newResponse);
                    pushFinalizing = true;
                    break;
                }
                pollCount--;
            }
            while (pollCount > 0);
        }

        // OTP: Send the input
        if (!pushFinalizing && oldResponse.promptForOTP)
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
            pam_syslog(pamh, LOG_ERR, "Unable to authenticate with privacyIDEA: %s (Code: %d)", newResponse.errorMessage.c_str(),
                       newResponse.errorCode);
            break;
        }
        else if (newResponse.transactionID.empty())
        {
            success = newResponse.authenticationSuccess;
            break;
        }

        oldResponse = newResponse;
    } // End loop

    closelog();
    return success ? PAM_SUCCESS : PAM_AUTH_ERR;
}

