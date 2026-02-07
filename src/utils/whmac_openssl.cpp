#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <cstddef>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <string>
#include "totp/error.hpp"
#include "totp/whmac.hpp"
#include "totp/totp.hpp"

namespace {
  using namespace whmac;

  char* getAlgoName(totp::SHA algo) {
    static auto opensslAlgo = std::array<std::string, 3>{ "SHA1", "SHA256", "SHA512" };
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    return opensslAlgo[static_cast<size_t>(algo)].data();
  }
}

namespace whmac {
  std::expected<Handle, totp::Error> Handle::make(totp::SHA algo) {
    if (algo > totp::SHA::SHA512) {
      return std::unexpected(totp::Error::InvalidAlgo);
    }

    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac == nullptr) {
      return std::unexpected(totp::Error::WhmacError);
    }

    Handle handle{};
    handle.mMac = mac;
    handle.mAlgo = algo;

    handle.mMacParams[0] = OSSL_PARAM_construct_utf8_string(
        "digest",
        getAlgoName(algo),
        0
        );
    handle.mMacParams[1] = OSSL_PARAM_construct_end();
    return handle;
  }

  Handle::~Handle(){
    EVP_MAC_free(mMac);
  }

  size_t Handle::getLen() const {
    return mLen;
  }

  totp::Error Handle::setKey(unsigned char* buffer, size_t buflen) {
    mCtx = EVP_MAC_CTX_new(mMac);
    if ((mCtx != nullptr) && (EVP_MAC_init (mCtx, buffer, buflen, mMacParams.data()) == 0)) {
      ERR_print_errors_fp(stderr);
      return totp::Error::InvalidAlgo;
    }
    mLen = EVP_MAC_CTX_get_mac_size (mCtx);
    return totp::Error::NoError;
  }

  void Handle::update(
      unsigned char *buffer,
      size_t buflen)
  {
    EVP_MAC_update (mCtx, buffer, buflen);
  }

  ssize_t Handle::finalize(
      unsigned char *buffer,
      size_t buflen)
  {
    size_t dlen = EVP_MAC_CTX_get_mac_size (mCtx);
    if (buffer == nullptr) {
      return ssize_t(dlen);
    }

    if (dlen > buflen) {
      return static_cast<ssize_t>(totp::Error::MemoryAllocationError);
    }

    EVP_MAC_final (mCtx, buffer, &dlen, buflen);
    EVP_MAC_CTX_free (mCtx);
    mCtx = nullptr;

    return ssize_t(dlen);
  }
}
