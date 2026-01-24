#ifndef TOTP_H
#define TOTP_H
#include <string>

namespace otp
{

std::string getTOTP(const std::string& secret, long epochSeconds);

}
#endif // TOTP_H
