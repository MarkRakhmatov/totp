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
/*! \brief whmac
 *
 */
namespace whmac {
  /*!
   * \brief The Handle class
   *
   *
   */
  struct Handle
  {
    Handle() = default;
    explicit Handle(totp::SHA algo);
    Handle(Handle&) = delete;
    Handle& operator=(Handle&) = delete;
    Handle(Handle&& other) noexcept:
      mac(other.mac),
      macParams(other.macParams),
      ctx(other.ctx),
      algo(other.algo),
      dlen(other.dlen){

      other.invalidate();
    }
    Handle& operator=(Handle&& other)  noexcept {
      mac = other.mac;
      macParams = other.macParams;
      ctx = other.ctx;
      algo = other.algo;
      dlen = other.dlen;

      other.invalidate();
      return *this;
    }
    ~Handle();
    [[nodiscard]] bool isValid() const {
      return mac != nullptr;
    }

    void invalidate() {
      mac = nullptr;
    }

    EVP_MAC *mac{nullptr};
    std::array<OSSL_PARAM, 4> macParams{};
    EVP_MAC_CTX *ctx{nullptr};
    totp::SHA algo{};
    size_t dlen{0};
  };

  size_t getLen(Handle& handle);

  totp::Error setKey(
      Handle& handle,
      unsigned char *buffer,
      size_t buflen);

  void update(
      Handle& handle,
      unsigned char *buffer,
      size_t buflen);

  ssize_t finalize(
      Handle& handle,
      unsigned char *buffer,
      size_t buflen);
}
