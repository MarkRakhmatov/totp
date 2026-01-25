#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <cstddef>
#include <array>
#include <cstdio>
#include <cstdlib>
#include "totp/whmac.hpp"
#include "totp/cotp.hpp"

const std::array<const char*, 3> openssl_algopp{
    "SHA1",
    "SHA256",
    "SHA512",
};

int
whmac_check ()
{
  return 0;
}

size_t
whmac_getlen (whmac_handle_t& hd)
{
  return hd.dlen;
}

whmac_handle_t whmac_gethandle(otp::SHA algo)
{
  whmac_handle_t whmac_handle{};

  if (algo > otp::SHA::SHA512) {
    return whmac_handle;
  }

  EVP_MAC *mac = EVP_MAC_fetch (nullptr, "HMAC", nullptr);
  if (mac != nullptr) {
    whmac_handle.mac = mac;
    whmac_handle.algo = algo;

    whmac_handle.mac_params[0] = OSSL_PARAM_construct_utf8_string(
        "digest",
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast, cppcoreguidelines-pro-bounds-constant-array-index)
        const_cast<char *>(openssl_algopp[(static_cast<int>(algo))]),
        0
    );
    whmac_handle.mac_params[1] = OSSL_PARAM_construct_end ();
  }

  return whmac_handle;
}

void whmac_freehandle (whmac_handle_t& hd)
{
  EVP_MAC_free (hd.mac);
}

otp::error
whmac_setkey (whmac_handle_t& hd,
             unsigned char  *buffer,
             size_t          buflen)
{
  hd.ctx = EVP_MAC_CTX_new (hd.mac);
  if ((hd.ctx != nullptr) && (EVP_MAC_init (hd.ctx, buffer, buflen, hd.mac_params.data()) == 0)) {
    ERR_print_errors_fp (stderr);
    return otp::error::INVALID_ALGO;
  }
  hd.dlen = EVP_MAC_CTX_get_mac_size (hd.ctx);
  return otp::error::NO_ERROR;
}

void
whmac_update (whmac_handle_t& hd,
             unsigned char  *buffer,
             size_t          buflen)
{
  EVP_MAC_update (hd.ctx, buffer, buflen);
}

ssize_t
whmac_finalize(whmac_handle_t& hd,
               unsigned char  *buffer,
               size_t          buflen)
{
  size_t dlen = EVP_MAC_CTX_get_mac_size (hd.ctx);
  if (buffer == nullptr) {
    return ssize_t(dlen);
  }

  if (dlen > buflen) {
    return static_cast<ssize_t>(otp::error::MEMORY_ALLOCATION_ERROR);
  }

  EVP_MAC_final (hd.ctx, buffer, &dlen, buflen);
  EVP_MAC_CTX_free (hd.ctx);
  hd.ctx = nullptr;

  return ssize_t(dlen);
}
