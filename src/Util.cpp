#include "Util.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

void DebugPrint(const std::string &msg)
{
    std::string filename = "/home/osboxes/testlog.txt";

    std::ofstream outfile;
    outfile.open(filename, std::ios_base::app); // append to end of file
    outfile << msg; // write string to file
    outfile.close();
}

std::string UrlEncode(const std::string& input) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : input) {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
            // Any other characters are percent-encoded
        else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char) c);
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}
