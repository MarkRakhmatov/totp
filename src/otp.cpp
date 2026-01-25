#include "totp/cotp.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cctype>
#include "totp/error.hpp"
#include "totp/whmac.hpp"
#include <base32/base32.hpp>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

namespace otp
{
  constexpr int MIN_PERIOD = 0;
  constexpr int MAX_PERIOD = 120;
  constexpr int MIN_DIGTS = 4;
  constexpr int MAX_DIGITS = 10;
  constexpr size_t BYTE_SIZE = 8;

  static void secure_memzero(volatile uchar *ptr, size_t n) {
    while ((n--) != 0U) {
      *ptr++ = 0;
    }
  }
  constexpr void reverse_bytes(long long count, std::array<uchar, BYTE_SIZE>& C_reverse_byte_order)
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  {
    for (size_t j = 0, i = BYTE_SIZE - 1; j < C_reverse_byte_order.size(); j++, i--) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      C_reverse_byte_order.at(i) = reinterpret_cast<uchar *>(&count)[j];
    }
  }
  #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  {
    for (size_t j = 0; j < C_reverse_byte_order.size(); j++) {
      (C_reverse_byte_order)[j] = ((uchar *)&(count))[j];
    }
  }
  #else
  #error "Unknown endianness"
  #endif

  static std::string normalize_secret (const char  *str);

  static int    truncate         (const uchar *hmac,
                      int          digits_length,
                      whmac_handle_t& handle);

  static std::vector<uchar> compute_hmac     (const char  *str,
                             long long        count,
                             whmac_handle_t& handle);

  static std::string finalize         (int          digits_length,
                        int          token);

  static error    check_period     (int          period);

  static error    check_otp_len    (int          digits_length);

  static error    check_algo       (SHA          algo);

  constexpr int g_decimal_base = 10;
  constexpr int g_mod_step = 10ULL;


  std::string
  get_hotp (const char   *secret,
           Counter     counter,
           DigitsCount           digits,
           SHA           algo,
           error *err_code)
  {
    if (whmac_check () == -1) {
      *err_code = error::WCRYPT_VERSION_MISMATCH;
      return {};
    }

    if (check_algo (algo) == error::INVALID_ALGO) {
      *err_code = error::INVALID_ALGO;
      return {};
    }

    if (check_otp_len (digits.value) == error::INVALID_DIGITS) {
      *err_code = error::INVALID_DIGITS;
      return {};
    }

    if (counter.value < 0) {
      *err_code = error::INVALID_COUNTER;
      return {};
    }

    whmac_handle_t handle = whmac_gethandle(algo);
    if (!handle.valid()) {
      return {};
    }

    auto hmac = compute_hmac (secret, counter.value, handle);
    if (hmac.empty()) {
      *err_code = error::WHMAC_ERROR;
      whmac_freehandle(handle);
      return {};
    }

    size_t const dlen = whmac_getlen(handle);
    int const token = truncate (hmac.data(), digits.value, handle);
    whmac_freehandle(handle);

    secure_memzero(hmac.data(), dlen);

    *err_code = error::NO_ERROR;

    return finalize (digits.value, token);
  }


  std::string
  get_totp_at (const char   *secret,
              long long     time,
              DigitsCount           digits,
              Period           period,
              SHA algo,
              error *err_code)
  {
    if (whmac_check () == -1) {
      *err_code = error::WCRYPT_VERSION_MISMATCH;
      return {};
    }

    if (check_otp_len (digits.value) == error::INVALID_DIGITS) {
      *err_code = error::INVALID_DIGITS;
      return {};
    }

    if (check_period (period.value) == error::INVALID_PERIOD) {
      *err_code = error::INVALID_PERIOD;
      return {};
    }

    error err = error::NO_ERROR;
    const auto& totp = get_hotp (secret, Counter(time / period.value), digits, algo, &err);
    if (err != error::NO_ERROR && err != error::VALID) {
      *err_code = err;
      return {};
    }

    *err_code = error::NO_ERROR;

    return totp;
  }


  std::string
  get_totp (const char   *secret,
           DigitsCount           digits,
           Period           period,
           SHA           algo,
           error *err_code)
  {
    return get_totp_at (secret, (long)time(nullptr), digits, period, algo, err_code);
  }


  int64_t
  otp_to_int (const char   *otp,
             error *err_code)
  {
    size_t const len = strlen (otp);
    if (len < MIN_DIGTS || len > MAX_DIGITS) {
      *err_code = error::INVALID_USER_INPUT;
      return -1;
    }

    if (otp[0] == '0') { // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      *err_code = error::MISSING_LEADING_ZERO;
    } else {
      *err_code = error::NO_ERROR;
    }

    return strtoll (otp, nullptr, g_decimal_base);
  }


  static std::string
  normalize_secret (const char *str)
  {
    auto norm_str = std::string(strlen (str), '\0');
    for (int i = 0, j = 0; str[i] != '\0'; i++) {
      if (int(str[i]) <= -1 || ((isalnum(str[i]) == 0) && str[i] != '='&& str[i] != ' ')) {
        return {};
      }
      if (str[i] != ' ') {
        norm_str.at(j++) = islower(str[i]) != 0 ? (char) toupper(str[i]) : str[i];
      }
    }
    return norm_str;
  }


  static int
  truncate (const uchar *hmac,
           int            digits_length,
           whmac_handle_t& handle)
  {
    // take the lower four bits of the last byte
    size_t const hlen = whmac_getlen(handle);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t const offset = hmac[hlen - 1] & 0x0fU;

    // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    uint32_t const bin_code = ((uint32_t)(hmac[offset] & 0x7fU) << 24U) | ((uint32_t)(hmac[offset + 1] & 0xffU) << 16U) | ((uint32_t)(hmac[offset + 2] & 0xffU) << 8U) | ((uint32_t)(hmac[offset + 3U] & 0xffU));

    uint64_t mod = 1;
    for (int i = 0; i < digits_length; ++i) {
      mod *= g_mod_step;
    }
    int const token = (int)(((uint64_t)bin_code) % mod);

    return token;
  }


  static std::vector<uchar>
  compute_hmac (const char *str,
               long long    count,
               whmac_handle_t& handle)
  {
    auto normalized_K = normalize_secret (str);
    if (normalized_K.empty()) {
      return {};
    }

    base32::error b32_err{};
    auto secret = base32::decode(normalized_K, b32_err);
    if (secret.empty()) {
      return {};
    }

    std::array<uchar, BYTE_SIZE> C_reverse_byte_order{};
    reverse_bytes(count, C_reverse_byte_order);

    auto err = whmac_setkey (handle, secret.data(), secret.size());
    if (err != error::NO_ERROR) {
      return {};
    }
    whmac_update (handle, C_reverse_byte_order.data(), sizeof(C_reverse_byte_order));

    size_t const dlen = whmac_getlen (handle);

    auto hmac = std::vector<uchar>(dlen, ' ');

    ssize_t const flen = whmac_finalize (handle, hmac.data(), dlen);
    if (flen < 0) {
      secure_memzero(hmac.data(), dlen);
      return {};
    }

    return hmac;
  }


  static std::string
  finalize (int digits_length,
           int tok)
  {
    std::ostringstream oss;
    oss << std::setw(digits_length) << std::setfill('0') << tok;
    return oss.str();
  }


  static error
  check_period (int period)
  {
    return (period <= MIN_PERIOD || period > MAX_PERIOD) ? error::INVALID_PERIOD : error::VALID;
  }


  static error
  check_otp_len (int digits_length)
  {
    return (digits_length < MIN_DIGTS || digits_length > MAX_DIGITS) ? error::INVALID_DIGITS : error::VALID;
  }


  static error
  check_algo (SHA algo)
  {
    return (algo != SHA::SHA1 && algo != SHA::SHA256 && algo != SHA::SHA512) ? error::INVALID_ALGO : error::VALID;
  }
}
