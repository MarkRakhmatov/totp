#include "totp/totp.hpp"
#include "totp/error.hpp"
#include "totp/whmac.hpp"
#include <base32/base32.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cctype>
#include <array>
#include <expected>
#include <string>
#include <string_view>
#include <sstream>
#include <iomanip>
#include <vector>

namespace {
  constexpr int gMinPeriod = 0;
  constexpr int gMaxPeriod = 120;
  constexpr int gMinDigits = 4;
  constexpr int gMaxDigits = 10;
  constexpr size_t gByteSize = 8;
}

namespace totp
{
  static void secureMemzero(std::vector<uchar>& ptr) {
    for(volatile uchar& ch: ptr) {
      ch = 0;
    }
  }

  constexpr void reverseBytes(long long count, std::array<uchar, gByteSize>& cReverseByteOrder)
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  {
    for (size_t j = 0, i = gByteSize - 1; j < cReverseByteOrder.size(); j++, i--) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast)
      cReverseByteOrder.at(i) = reinterpret_cast<uchar *>(&count)[j];
    }
  }
  #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  {
    for (size_t j = 0; j < C_reverse_byte_order.size(); j++) {
      C_reverse_byte_order.at(j) = reinterpret_cast<uchar *>(&count)[j];
    }
  }
  #else
  #Error "Unknown endianness"
  #endif

  static std::string normalizeSecret(std::string_view str);

  static int truncate(
      const std::vector<uchar>& hmac,
      int digitsLength,
      whmac::Handle& handle);

  static std::vector<uchar> computeHmac(
      std::string_view str,
      long long count,
      whmac::Handle& handle);

  static std::string finalize(
      int digitsLength,
      int token);

  static Error checkPeriod(int period);

  static Error checkOtpLen(int digitsLength);

  static Error checkAlgo(SHA algo);

  constexpr int gModStep = 10ULL;

  std::expected<std::string, Error> getHotp(
      const char *base32EncodedSecret,
      Counter counter,
      DigitsCount digits,
      SHA algo)
  {
    if (checkAlgo(algo) == Error::InvalidAlgo) {
      return std::unexpected(Error::InvalidAlgo);
    }

    if (checkOtpLen (digits.value) == Error::InvalidDigits) {
      return std::unexpected(Error::InvalidDigits);
    }

    if (counter.value < 0) {
      return std::unexpected(Error::InvalidCounter);
    }

    auto handle = whmac::Handle(algo);
    if (!handle.isValid()) {
      return std::unexpected(Error::WhmacError);
    }

    auto hmac = computeHmac(base32EncodedSecret, counter.value, handle);
    if (hmac.empty()) {
      return std::unexpected(Error::WhmacError);
    }

    int const token = truncate(hmac, digits.value, handle);

    secureMemzero(hmac);

    return finalize(digits.value, token);
  }

  std::expected<std::string, Error> getTotpAt(
      const char *secret,
      long long time,
      DigitsCount digits,
      Period period,
      SHA algo)
  {
    if (checkOtpLen(digits.value) == Error::InvalidDigits) {
      return std::unexpected(Error::InvalidDigits);
    }

    if (checkPeriod (period.value) == Error::InvalidPeriod) {
      return std::unexpected(Error::InvalidPeriod);
    }

    const auto& totp = getHotp(secret, Counter(time / period.value), digits, algo);
    if (!totp.has_value()) {
      return std::unexpected(totp.error());
    }

    return totp;
  }


  std::expected<std::string, Error> getTotp (
    const char *secret,
    DigitsCount digits,
    Period period,
    SHA algo)
  {
    return getTotpAt (secret, (long)time(nullptr), digits, period, algo);
  }


  std::expected<int64_t, Error> totpToInt(const std::string& otp)
  {
    size_t const len = otp.length();
    if (len < gMinDigits || len > gMaxDigits) {
      return std::unexpected(Error::InvalidUserInput);
    }

    return std::stoll(otp, nullptr);
  }


  static std::string normalizeSecret(std::string_view str)
  {
    auto normStr = std::string{};
    normStr.reserve(str.size());
    for (auto ch : str) {
      if (int(ch) <= -1 || ((::isalnum(ch) == 0) && ch != '='&& ch != ' ')) {
        return {};
      }
      if (ch != ' ') {
        normStr.push_back(
            ::islower(ch) != 0 ? static_cast<char>(::toupper(ch)) : ch
        );
      }
    }
    return normStr;
  }


  static int truncate(
      const std::vector<uchar>& hmac,
      int digitsLength,
      whmac::Handle& handle)
  {
    // take the lower four bits of the last byte
    size_t const hlen = handle.dlen;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t const offset = hmac[hlen - 1] & 0x0fU;

    // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t const binCode = ((uint32_t)(hmac[offset] & 0x7fU) << 24U) | ((uint32_t)(hmac[offset + 1] & 0xffU) << 16U) | ((uint32_t)(hmac[offset + 2] & 0xffU) << 8U) | ((uint32_t)(hmac[offset + 3U] & 0xffU));

    uint64_t mod = 1;
    for (int i = 0; i < digitsLength; ++i) {
      mod *= gModStep;
    }
    int const token = (int)(((uint64_t)binCode) % mod);

    return token;
  }


  static std::vector<uchar> computeHmac(
      std::string_view str,
      long long count,
      whmac::Handle& handle)
  {
    auto normalizedSecret = normalizeSecret(str);
    if (normalizedSecret.empty()) {
      return {};
    }

    base32::Error b32Err{};
    auto secret = base32::decode(normalizedSecret, b32Err);
    if (secret.empty()) {
      return {};
    }

    std::array<uchar, gByteSize> cReverseByteOrder{};
    reverseBytes(count, cReverseByteOrder);

    auto err = setKey (handle, secret.data(), secret.size());
    if (err != Error::NoError) {
      return {};
    }
    update(handle, cReverseByteOrder.data(), sizeof(cReverseByteOrder));

    size_t const dlen = handle.dlen;

    auto hmac = std::vector<uchar>(dlen, ' ');

    ssize_t const flen = finalize(handle, hmac.data(), dlen);
    if (flen < 0) {
      secureMemzero(hmac);
      return {};
    }

    return hmac;
  }


  static std::string finalize(
      int digitsLength,
      int tok)
  {
    std::ostringstream oss;
    oss << std::setw(digitsLength) << std::setfill('0') << tok;
    return oss.str();
  }


  static Error checkPeriod(int period)
  {
    return (period <= gMinPeriod || period > gMaxPeriod) ? Error::InvalidPeriod : Error::Valid;
  }


  static Error checkOtpLen(int digitsLength)
  {
    return (digitsLength < gMinDigits || digitsLength > gMaxDigits) ? Error::InvalidDigits : Error::Valid;
  }


  static Error checkAlgo(SHA algo)
  {
    return (algo < SHA::SHA1 || algo > SHA::SHA512) ? Error::InvalidAlgo : Error::Valid;
  }
}
