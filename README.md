# PAM Module for Authentication with PrivacyIDEA

## Features
* OTP Token
* Challenge-Response Token, incl. PUSH
* Offline with HOTP Token
* Multi-Challenge

## Build
This project requires the [very good JSON parser from nlohmann](https://github.com/nlohmann/json). Put the single include file `json.hpp` in `include`.

It also requires the following libraries: `libcurl4-openssl-dev`, `libssl-dev`, `libpam0g-dev`

Compile with:

    g++ -Wall -fPIC -g -Iinclude -c /path/to/src/pam_privacyidea.cpp -o obj/(Debug/Release)/src/pam_privacyidea.o
    g++ -Wall -fPIC -g -Iinclude -c /path/to/src/PrivacyIDEA.cpp -o obj/(Debug/Release)/src/PrivacyIDEA.o
    g++ -shared  obj/(Debug/Release)/src/pam_privacyidea.o obj/(Debug/Release)/src/PrivacyIDEA.o  -o bin/(Debug/Release)/pam_privacyidea.so -Wno-undef  -lcurl

## Configuration
The following values can be appended to the pam config file line that references this module:
| Name     | Description |
|:--------:|:----------------|
|url=|Required. URL of privacyIDEA.|
|nossl|Disable SSL certificate check. DO NOT USE IN PRODUCTION!|
|realm=|Specify the privacyIDEA realm.|
|sendEmptyPass|Sends the username and an empty pass to privacyidea prior to asking for OTP. Can be used to trigger challenges.|
|sendUnixPass|Sends the username and the password to privacyidea prior to asking for OTP. Can be used to trigger challenges. Takes precedence over `sendemptypass`.|
|offlineFile=|Set the path to the offline file. (default is /etc/privacyidea/pam.txt).|
|pollTime=|Set the time in seconds to poll for successful push auth. Default is 0, meaning only once. Polls twice per second.|
|debug|Enable debug logging.|

### Notes
#### Push behavior
If only push and **no** OTP token were triggered, the module will poll for the configured time without prompting the user for input.

If both push and OTP token were triggered, the module will prompt for the OTP and poll **once** after the user presses enter. The user can press enter with empty input to use push, just make sure the authentication was already confirmed on the smartphone.

#### SSH
Set `ChallengeResponseAuthentication yes` in `/etc/ssh/sshd_config` (or similar).
