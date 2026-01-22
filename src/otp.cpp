#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cctype>
#include "totp/whmac.hpp"
#include "totp/cotp.hpp"
#include <base32/base32.hpp>
#include <memory>
#include <array>

#ifdef _MSC_VER
#define strdup _strdup
#endif

template<typename T>
using cmem_guard = std::unique_ptr<T, decltype(&free)>;

static void secure_memzero(void *ptr, size_t n) {
  auto *vptr = static_cast<volatile unsigned char *>(ptr);
  while ((n--) != 0U) {
    *vptr++ = 0;
  }
}
constexpr size_t byte_size = 8;
constexpr void reverse_bytes(long long count, std::array<unsigned char, 8>& C_reverse_byte_order)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
{
  for (size_t j = 0, i = 7; j < C_reverse_byte_order.size(); j++, i--) {
    C_reverse_byte_order[i] = ((unsigned char *)&(count))[j];
  }
}
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
{
  for (size_t j = 0; j < C_reverse_byte_order.size(); j++) {
    (C_reverse_byte_order)[j] = ((unsigned char *)&(count))[j];
  }
}
#else
#error "Unknown endianness"
#endif

static cmem_guard<char> normalize_secret (const char  *str);

static int    truncate         (const uchar *hmac,
                    int          digits_length,
                    whmac_handle_t *handle);

static cmem_guard<unsigned char> compute_hmac     (const char  *str,
                           long long        count,
                           whmac_handle_t *hd);

static char  *finalize         (int          digits_length,
                      int          token);

static int    check_period     (int          period);

static int    check_otp_len    (int          digits_length);

static int    check_algo       (int          algo);

constexpr int g_decimal_base = 10;
constexpr int g_mod_step = 10ULL;


char *
get_hotp (const char   *secret,
         long long     counter,
         int           digits,
         int           algo,
         cotp_error_t *err_code)
{
  if (whmac_check () == -1) {
    *err_code = WCRYPT_VERSION_MISMATCH;
    return nullptr;
  }

  if (check_algo (algo) == INVALID_ALGO) {
    *err_code = INVALID_ALGO;
    return nullptr;
  }

  if (check_otp_len (digits) == INVALID_DIGITS) {
    *err_code = INVALID_DIGITS;
    return nullptr;
  }

  if (counter < 0) {
    *err_code = INVALID_COUNTER;
    return nullptr;
  }

  whmac_handle_t *handle = whmac_gethandle (algo);
  if (handle == nullptr) {
    return nullptr;
  }

  auto const hmac = compute_hmac (secret, counter, handle);
  if (hmac == nullptr) {
    *err_code = WHMAC_ERROR;
    whmac_freehandle(handle);
    return nullptr;
  }

  size_t const dlen = whmac_getlen(handle);
  int const token = truncate (hmac.get(), digits, handle);
  whmac_freehandle(handle);

  secure_memzero(hmac.get(), dlen);

  *err_code = NO_ERROR;

  return finalize (digits, token);
}


char *
get_totp_at (const char   *secret,
            long long     current_timestamp,
            int           digits,
            int           period,
            int           algo,
            cotp_error_t *err_code)
{
  if (whmac_check () == -1) {
    *err_code = WCRYPT_VERSION_MISMATCH;
    return nullptr;
  }

  if (check_otp_len (digits) == INVALID_DIGITS) {
    *err_code = INVALID_DIGITS;
    return nullptr;
  }

  if (check_period (period) == INVALID_PERIOD) {
    *err_code = INVALID_PERIOD;
    return nullptr;
  }

  cotp_error_t err = NO_ERROR;
  char *totp = get_hotp (secret, current_timestamp / period, digits, algo, &err);
  if (err != NO_ERROR && err != VALID) {
    *err_code = err;
    return nullptr;
  }

  *err_code = NO_ERROR;

  return totp;
}


char *
get_totp (const char   *secret,
         int           digits,
         int           period,
         int           algo,
         cotp_error_t *err_code)
{
  return get_totp_at (secret, (long)time(nullptr), digits, period, algo, err_code);
}


int64_t
otp_to_int (const char   *otp,
           cotp_error_t *err_code)
{
  size_t const len = strlen (otp);
  if (len < MIN_DIGTS || len > MAX_DIGITS) {
    *err_code = INVALID_USER_INPUT;
    return -1;
  }

  if (otp[0] == '0') {
    *err_code = MISSING_LEADING_ZERO;
  } else {
    *err_code = NO_ERROR;
  }

  return strtoll (otp, nullptr, g_decimal_base);
}


static cmem_guard<char>
normalize_secret (const char *str)
{
  auto norm_str = cmem_guard<char>{static_cast<char*>(calloc (strlen (str) + 1, 1)), &free};
  if (norm_str == nullptr) {
    return norm_str;
  }
  for (int i = 0, j = 0; str[i] != '\0'; i++) {
    if (int(str[i]) <= -1 || ((isalnum(str[i]) == 0) && str[i] != '='&& str[i] != ' ')) {
      return {nullptr, &free};
    }
    if (str[i] != ' ') {
      norm_str.get()[j++] = islower(str[i]) != 0 ? (char) toupper(str[i]) : str[i];
    }
  }
  return norm_str;
}


static int
truncate (const unsigned char *hmac,
         int            digits_length,
         whmac_handle_t *handle)
{
  // take the lower four bits of the last byte
  size_t const hlen = whmac_getlen(handle);
  int const offset = hmac[hlen - 1] & 0x0f;

  // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
  uint32_t bin_code = ((uint32_t)(hmac[offset] & 0x7f) << 24) | ((uint32_t)(hmac[offset + 1] & 0xff) << 16) | ((uint32_t)(hmac[offset + 2] & 0xff) << 8) | ((uint32_t)(hmac[offset + 3] & 0xff));

  uint64_t mod = 1;
  for (int i = 0; i < digits_length; ++i) {
    mod *= g_mod_step;
  }
  int const token = (int)(((uint64_t)bin_code) % mod);

  return token;
}


static cmem_guard<unsigned char>
compute_hmac (const char *str,
             long long    count,
             whmac_handle_t *handle)
{
  auto normalized_K = normalize_secret (str);
  if (normalized_K == nullptr) {
    return {nullptr, &free};
  }

  base32::error b32_err{};
  auto secret = base32::decode(normalized_K.get(), b32_err);
  if (secret.empty()) {
    return {nullptr, &free};
  }

  std::array<unsigned char, byte_size> C_reverse_byte_order{};
  reverse_bytes(count, C_reverse_byte_order);

  auto err = whmac_setkey (handle, secret.data(), secret.size());
  if (err != cotp_error_t::NO_ERROR) {
    return {nullptr, &free};
  }
  whmac_update (handle, C_reverse_byte_order.data(), sizeof(C_reverse_byte_order));

  size_t const dlen = whmac_getlen (handle);
  auto hmac = cmem_guard<unsigned char>{static_cast<unsigned char*>(calloc (dlen, 1)), &free};
  if (hmac == nullptr) {
    return {nullptr, &free};
  }

  ssize_t const flen = whmac_finalize (handle, hmac.get(), dlen);
  if (flen < 0) {
    secure_memzero(hmac.get(), dlen);
    return {nullptr, &free};
  }

  return hmac;
}


static char *
finalize (int digits_length,
         int tok)
{
  char *token = (char*)calloc (digits_length + 1, 1);
  if (token == nullptr) {
    return nullptr;
  }
  // Print with leading zeros without building an intermediate format string
  snprintf (token, digits_length + 1, "%0*d", digits_length, tok);
  return token;
}


static int
check_period (int period)
{
  return (period <= MIN_PERIOD || period > MAX_PERIOD) ? INVALID_PERIOD : VALID;
}


static int
check_otp_len (int digits_length)
{
  return (digits_length < MIN_DIGTS || digits_length > MAX_DIGITS) ? INVALID_DIGITS : VALID;
}


static int
check_algo (int algo)
{
  return (algo != SHA1 && algo != SHA256 && algo != SHA512) ? INVALID_ALGO : VALID;
}
