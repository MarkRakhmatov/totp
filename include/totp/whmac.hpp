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

struct WhmacHandle
{
  EVP_MAC *mac;
  std::array<OSSL_PARAM, 4> macParams;
  EVP_MAC_CTX *ctx;
  totp::SHA algo;
  size_t dlen;

  [[nodiscard]] bool valid() const {
    return mac != nullptr;
  }
};

WhmacHandle whmacGetHandle(totp::SHA algo);

size_t whmacGetlen(WhmacHandle& handle);

void whmacFreeHandle(WhmacHandle& handle);

totp::Error whmacSetKey(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen);

void whmacUpdate(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen);

ssize_t whmacFinalize(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen);
