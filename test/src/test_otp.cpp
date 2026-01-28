#include <boost/ut.hpp>
#include <totp/totp.hpp>
#include <base32/base32.hpp>
#include <string>
#include <chrono>

using namespace boost::ut;
using namespace totp;

using namespace std::chrono_literals;
using namespace std::chrono;

suite<"c otp"> cotp = [] {
  test("totp_rfc6238 test_8_digits_SHA::SHA1") = []{
      const std::string my_string= "12345678901234567890";
      const long long counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
      const char *expected_totp[] = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};

      base32::Error b32_err{};
      auto K_base32 = base32::encode(base32::Bytes(my_string.begin(), my_string.end()), b32_err);

      for (int i = 0; i < 6; i++) {
          const auto& totp = GetTotpAt(K_base32.c_str(), counter[i], DigitsCount(8), Period(30), SHA::SHA1);
          expect (totp == std::string(expected_totp[i]));
      }
    };

  test("totp_rfc6238, test_8_digits_SHA::SHA1_toint") = []{
      const auto K = std::string("12345678901234567890");
      const long long counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
      const int64_t expected_totp[] = {94287082, 7081804, 14050471, 89005924, 69279037, 65353130};

      base32::Error b32_err{};
      auto K_base32 = base32::encode(base32::Bytes(K.begin(), K.end()), b32_err);

      for (int i = 0; i < 6; i++) {
          const auto& totp = GetTotpAt(K_base32.c_str(), counter[i], DigitsCount(8), Period(30), SHA::SHA1);
          auto int_totp = TotpToInt(totp.value());
          expect(int_totp == expected_totp[i]);
      }
  };

  test("totp_rfc6238, test_10_digits_SHA::SHA1") = []{
      std::string K = "12345678901234567890";
      const long counter = 1234567890;
      const char *expected_totp = "0689005924";

      base32::Error base32_err{};
      const auto& K_base32 = base32::encode(base32::Bytes(K.begin(), K.end()), base32_err);

      const auto& totp = GetTotpAt(K_base32.c_str(), counter, DigitsCount(10), Period(30), SHA::SHA1);
      expect(totp == std::string(expected_totp));
  };

  test("totp_rfc6238, test_10_digits_SHA::SHA1_toint") = []{
      std::string K = "12345678901234567890";
      const long counter = 1234567890;
      int64_t expected_totp = 689005924;

      base32::Error cotp_err{};
      const auto& K_base32 = base32::encode (base32::Bytes(K.begin(), K.end()), cotp_err);

      const auto& totp = GetTotpAt(K_base32.c_str(), counter, DigitsCount(10), Period(30), SHA::SHA1);
      auto int_totp = TotpToInt(totp.value());
      expect (int_totp == expected_totp);
  };

  test("totp_rfc6238, test_8_digits_SHA::SHA256") = []{
      std::string K = "12345678901234567890123456789012";
      const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
      const char *expected_totp[] = {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"};

      base32::Error cotp_err{};
      const auto& K_base32 = base32::encode (base32::Bytes(K.begin(), K.end()), cotp_err);

      for (int i = 0; i < 6; i++) {
          const auto& totp = GetTotpAt (K_base32.c_str(), counter[i], DigitsCount(8), Period(30), SHA::SHA256);
          expect(totp == std::string(expected_totp[i]));
      }
  };

  test("totp_rfc6238, test_8_digits_sha512") = []{
      std::string K = "1234567890123456789012345678901234567890123456789012345678901234";
      const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
      const char *expected_totp[] = {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"};

      base32::Error cotp_err{};
      const auto& K_base32 = base32::encode (base32::Bytes(K.begin(), K.end()), cotp_err);

      for (int i = 0; i < 6; i++) {
          const auto& totp = GetTotpAt (K_base32.c_str(), counter[i], DigitsCount(8), Period(30), SHA::SHA512);
          expect (totp == std::string(expected_totp[i]));
      }
  };

  test("hotp_rfc, test_6_digits") = []{
      std::string K = "12345678901234567890";
      const int counter[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
      std::string expected_hotp[] = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};

      base32::Error cotp_err{};
      const auto& K_base32 = base32::encode(base32::Bytes(K.begin(), K.end()), cotp_err);

      for (int i = 0; i < 10; i++) {
          const auto hotp = GetHOTP (K_base32.c_str(), Counter(counter[i]), DigitsCount(6), SHA::SHA1);
          expect(hotp == expected_hotp[i]);
      }
  };

  test("hotp_rfc, test_wrong_digits_2") = []{
      std::string K = "this is a secret";

      const auto& totp = GetTotp(K.c_str(), DigitsCount(2), Period(30), SHA::SHA1);

      expect (totp.error() == Error::InvalidDigits);
  };


  test("hotp_rfc, test_wrong_digits_16") = []{
      std::string K = "this is a secret";

      const auto& totp = GetTotp(K.c_str(), DigitsCount(16), Period(30), SHA::SHA1);

      expect (totp.error() == Error::InvalidDigits);
  };


  test("hotp_rfc, test_period_zero") = []{
      std::string K = "this is a secret";

      const auto& totp = GetTotp (K.c_str(), DigitsCount(6), Period(0), SHA::SHA1);

      expect (totp.error() == Error::InvalidPeriod);
  };


  test("hotp_rfc, test_totp_wrong_negative") = []{
      std::string K = "this is a secret";

      const auto& totp = GetTotp(K.c_str(), DigitsCount(6), Period(-20), SHA::SHA1);

      expect (totp.error() == Error::InvalidPeriod);
  };


  test("hotp_rfc, test_hotp_wrong_negative") = []{
      std::string K = "this is a secret";

      const auto& hotp = GetHOTP(K.c_str(), Counter(-6), DigitsCount(8), SHA::SHA1);

      expect (hotp.error() == Error::InvalidCounter);
  };


  test("totp_generic, test_secret_with_space") = []{
      std::string K = "hxdm vjec jjws rb3h wizr 4ifu gftm xboz";
      std::string expected_totp = "488431";

      const auto& totp = GetTotpAt (K.c_str(), 1506268800, DigitsCount(6), Period(30), SHA::SHA1);
      expect (totp == expected_totp);
  };


  test("totp_generic, test_fail_invalid_b32_input") = []{
      std::string K = "This input is not valid!";

      const auto& totp = GetTotp (K.c_str(), DigitsCount(6), Period(30), SHA::SHA1);

      expect (totp.error() == Error::WhmacError);
  };


  test("totp_generic, test_fail_invalid_algo") = []{
      std::string K = "base32secret";

      int MD5 = 3;
      const auto& totp = GetTotp(K.c_str(), DigitsCount(6), Period(30), static_cast<SHA>(MD5));

      expect (totp.error() == Error::InvalidAlgo);
  };


  test("totp_rfc6238, test_60seconds") = []{
      std::string K = "12345678901234567890";
      std::string expected_totp = "360094";

      base32::Error cotp_err{};
      const auto& secret_base32 = base32::encode(base32::Bytes(K.begin(), K.end()), cotp_err);

      const auto& totp = GetTotpAt(secret_base32.c_str(), 1111111109, DigitsCount(6), Period(60), SHA::SHA1);
      expect (totp == expected_totp);
  };


  test("totp_int, test_err_is_missing_zero") = []{
      std::string K = "12345678901234567890";
      const long counter = 1234567890;

      base32::Error cotp_err{};
      const auto& K_base32 = base32::encode(base32::Bytes(K.begin(), K.end()), cotp_err);

      const auto& totp = GetTotpAt(K_base32.c_str(), counter, DigitsCount(10), Period(30), SHA::SHA1);
      auto int_totp = TotpToInt(totp.value());
      expect (int_totp == 689005924);
  };

  test("totp_int, test_err_invalid_input") = []{
      auto totp = TotpToInt ("124");
      expect (totp.error() == Error::InvalidUserInput);
  };

  test("GetTotpAt OK") = []{
    auto date = year_month_day(2020y, January, 1d);
    std::chrono::sys_days timestamp_days = date;
    auto epoch_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                             timestamp_days.time_since_epoch()
                             ).count();
    expect(epoch_seconds == 1577836800);
    auto totp = GetTotpAt(
        "IO3SKWXDGBFTDDJUGPPJA3KEQAKTGLCV",
        static_cast<long>(epoch_seconds));
    expect(totp.has_value());
    expect(std::string("309850") == totp);
  };

  test("invalid input ERROR") = []{
    auto totp = GetTotpAt("\226", 0);
    expect(totp.error() == Error::WhmacError);
    expect(!totp.has_value());
  };
};
