#pragma once

#include <openssl/evp.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <totp/error.hpp>

using ssize_t = long;


namespace totp {
  enum struct SHA: std::uint8_t;
}

struct whmac_handle_t
{
  EVP_MAC *mac;
  std::array<OSSL_PARAM, 4> mac_params;
  EVP_MAC_CTX *ctx;
  totp::SHA algo;
  size_t dlen;

  [[nodiscard]] bool valid() const {
    return mac != nullptr;
  }
};

int whmac_check();

whmac_handle_t whmac_gethandle(totp::SHA algo);

size_t          whmac_getlen     (whmac_handle_t& hd);

void            whmac_freehandle (whmac_handle_t& hd);

totp::error             whmac_setkey     (whmac_handle_t& hd,
                                  unsigned char  *buffer,
                                  size_t         buflen);

void            whmac_update     (whmac_handle_t& hd,
                                  unsigned char  *buffer,
                                  size_t         buflen);

ssize_t         whmac_finalize   (whmac_handle_t& hd,
                                  unsigned char  *buffer,
                                  size_t         buflen);

