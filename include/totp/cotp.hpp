#pragma once
#include <stdint.h>
#include <stdbool.h>

#define SHA1 0
#define SHA256 1
#define SHA512 2

#define MIN_DIGTS 4
#define MAX_DIGITS 10
constexpr int DEFAULT_DIGITS = 6;
constexpr int MIN_PERIOD = 0;
constexpr int DEFAULT_PERIOD = 30;
constexpr int MAX_PERIOD = 120;

typedef enum cotp_error {
    NO_ERROR = 0,
    VALID,
    WCRYPT_VERSION_MISMATCH,
    INVALID_B32_INPUT,
    INVALID_ALGO,
    INVALID_DIGITS,
    INVALID_PERIOD,
    MEMORY_ALLOCATION_ERROR,
    INVALID_USER_INPUT,
    EMPTY_STRING,
    MISSING_LEADING_ZERO,
    INVALID_COUNTER,
    WHMAC_ERROR
} cotp_error_t;

using uchar = unsigned char;

#ifdef __cplusplus
extern "C" {
#endif

bool     is_string_valid_b32 (const char *user_data);

char    *get_hotp          (const char   *base32_encoded_secret,
                            long long          counter,
                            int           digits,
                            int           sha_algo,
                            cotp_error_t *err_code);

char    *get_totp          (const char   *base32_encoded_secret,
                            int           digits,
                            int           period,
                            int           sha_algo,
                            cotp_error_t *err_code);

char    *get_totp_at       (const char   *base32_encoded_secret,
                            long long          time,
                            int           digits,
                            int           period,
                            int           sha_algo,
                            cotp_error_t *err_code);

int64_t  otp_to_int        (const char   *otp,
                            cotp_error_t *err_code);

#ifdef __cplusplus
}
#endif
