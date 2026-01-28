#pragma once

#include <openssl/evp.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <totp/Error.hpp>

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

  [[nodiscard]] bool Valid() const {
    return mac != nullptr;
  }
};

WhmacHandle WhmacGetHandle(totp::SHA algo);

size_t WhmacGetlen(WhmacHandle& handle);

void WhmacFreeHandle(WhmacHandle& handle);

totp::Error WhmacSetKey(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen);

void WhmacUpdate(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen);

ssize_t WhmacFinalize(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen);
