#pragma once

#include <openssl/evp.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
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
   */
  struct Handle
  {
    Handle() = default;
    [[nodiscard]] static std::expected<Handle, totp::Error> make(totp::SHA algo);
    Handle(Handle&) = delete;
    Handle& operator=(Handle&) = delete;
    Handle(Handle&& other) noexcept:
      mMac(other.mMac),
      mMacParams(other.mMacParams),
      mCtx(other.mCtx),
      mAlgo(other.mAlgo),
      mLen(other.mLen){

      other.invalidate();
    }
    Handle& operator=(Handle&& other)  noexcept {
      mMac = other.mMac;
      mMacParams = other.mMacParams;
      mCtx = other.mCtx;
      mAlgo = other.mAlgo;
      mLen = other.mLen;

      other.invalidate();
      return *this;
    }
    ~Handle();
    [[nodiscard]] bool isValid() const {
      return mMac != nullptr;
    }

    void invalidate() {
      mMac = nullptr;
    }

    [[nodiscard]] size_t getLen() const;

    totp::Error setKey(
        unsigned char *buffer,
        size_t buflen);

    void update(
        unsigned char *buffer,
        size_t buflen);

    ssize_t finalize(
        unsigned char *buffer,
        size_t buflen);
  private:
    EVP_MAC *mMac{nullptr};
    std::array<OSSL_PARAM, 4> mMacParams{};
    EVP_MAC_CTX *mCtx{nullptr};
    totp::SHA mAlgo{};
    size_t mLen{0};
  };
}
