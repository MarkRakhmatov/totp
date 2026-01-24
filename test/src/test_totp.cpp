#include "boost/ut.hpp"
#include <totp/totp.hpp>

#include <string>
#include <chrono>

using namespace std::chrono_literals;
using namespace std::chrono;
using namespace boost::ut;

suite<"cpp otp"> cpptotp = [] {
    test("getTOTP OK") = []{
      auto date = year_month_day(2020y, January, 1d);
      std::chrono::sys_days timestamp_days = date;
      auto epoch_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                               timestamp_days.time_since_epoch()
                               ).count();
      expect(epoch_seconds == 1577836800);
      auto totp = otp::getTOTP("IO3SKWXDGBFTDDJUGPPJA3KEQAKTGLCV", static_cast<long>(epoch_seconds));
      expect(std::string("309850") == totp);
  };

  test("invalid input ERROR") = []{
    auto totp = otp::getTOTP("\226", 0);
    expect (totp.empty());
  };
};
