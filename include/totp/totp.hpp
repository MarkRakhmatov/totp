#ifndef TOTP_H
#define TOTP_H
#include <memory>
#include <string>

namespace otp
{

using totp_guard = std::unique_ptr<char, decltype(&free)>;

totp_guard getTOTP(const std::string& secret, long epochSeconds);

}
#endif // TOTP_H
