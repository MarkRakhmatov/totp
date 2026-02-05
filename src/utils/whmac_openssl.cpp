#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <cstddef>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>
#include "totp/error.hpp"
#include "totp/whmac.hpp"
#include "totp/totp.hpp"

char* getAlgoName(totp::SHA algo) {
  static auto opensslAlgo = std::array<std::string, 3>{ "SHA1", "SHA256", "SHA512" };
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  return opensslAlgo[static_cast<size_t>(algo)].data();
}

WhmacHandle whmacGetHandle(totp::SHA algo)
{
  WhmacHandle handle{};

  if (algo > totp::SHA::SHA512) {
    return handle;
  }

  EVP_MAC *mac = EVP_MAC_fetch (nullptr, "HMAC", nullptr);
  if (mac == nullptr) {
    return handle;
  }

  handle.mac = mac;
  handle.algo = algo;

  handle.macParams[0] = OSSL_PARAM_construct_utf8_string(
      "digest",
      getAlgoName(algo),
      0
  );
  handle.macParams[1] = OSSL_PARAM_construct_end ();

  return handle;
}

void whmacFreeHandle(WhmacHandle& handle)
{
  EVP_MAC_free(handle.mac);
}

totp::Error whmacSetKey(WhmacHandle& handle, unsigned char* buffer, size_t buflen) {
  handle.ctx = EVP_MAC_CTX_new (handle.mac);
  if ((handle.ctx != nullptr) && (EVP_MAC_init (handle.ctx, buffer, buflen, handle.macParams.data()) == 0)) {
    ERR_print_errors_fp (stderr);
    return totp::Error::InvalidAlgo;
  }
  handle.dlen = EVP_MAC_CTX_get_mac_size (handle.ctx);
  return totp::Error::NoError;
}

void whmacUpdate(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen)
{
  EVP_MAC_update (handle.ctx, buffer, buflen);
}

ssize_t whmacFinalize(
    WhmacHandle& handle,
    unsigned char *buffer,
    size_t buflen)
{
  size_t dlen = EVP_MAC_CTX_get_mac_size (handle.ctx);
  if (buffer == nullptr) {
    return ssize_t(dlen);
  }

  if (dlen > buflen) {
    return static_cast<ssize_t>(totp::Error::MemoryAllocationError);
  }

  EVP_MAC_final (handle.ctx, buffer, &dlen, buflen);
  EVP_MAC_CTX_free (handle.ctx);
  handle.ctx = nullptr;

  return ssize_t(dlen);
}
