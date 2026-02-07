#pragma once
#include <cstdint>
#include <string>
#include <expected>
#include "totp/error.hpp"

/*! \mainpage TOTP
 *
 * \section intro_sec Introduction
 *
 * C++ 23 Time-based One-Time Password library
 *
 */

/*! \brief totp namespace
 *
 */
namespace totp
{
  /*!
   * \brief The SHA enum
   */
  enum struct SHA: std::uint8_t {
    SHA1 = 0,
    SHA256 = 1,
    SHA512 = 2
  };

  using uchar = unsigned char;

  /*!
   * \brief The Strong class is helper to provide strongly typed API parameters
   */
  template <class T, class Tag>
  struct Strong {
    /*!
     * \brief explicit constructor is required for strong typing
     * \param value
     */
    explicit constexpr Strong(T value) : value(value) {}
    /*!
     * \brief raw value
     */
    T value;
  };

  using Counter = Strong<long long, struct CounterTag>;
  using DigitsCount = Strong<int, struct DigitsTag>;
  using Period = Strong<int, struct PersiodTag>;
  /*!
   * \brief gDefaultDigits, most apps use 6 digits for OTP
   */
  constexpr DigitsCount gDefaultDigits(6);
  /*!
   * \brief gDefaultPeriod, most apps use 30 seconds OTP update period
   */
  constexpr Period gDefaultPeriod(30);
  /*!
   * \brief getHotp
   * \param base32EncodedSecret
   * \param counter
   * \param digits
   * \param shaAlgo
   * \return
   *
   * \callgraph
   */
  std::expected<std::string, Error> getHotp(
      const char *base32EncodedSecret,
      Counter counter,
      DigitsCount digits,
      SHA shaAlgo);
  /*!
   * \brief getTotp
   * \param base32EncodedSecret
   * \param digits
   * \param period
   * \param shaAlgo
   * \return
   *
   * \callgraph
   */
  std::expected<std::string, Error> getTotp(
      const char *base32EncodedSecret,
      DigitsCount digits,
      Period period,
      SHA shaAlgo=SHA::SHA1);
  /*!
   * \brief getTotpAt
   * \param base32EncodedSecret
   * \param time
   * \param digits
   * \param period
   * \param shaAlgo
   * \return
   *
   * \callgraph
   */
  std::expected<std::string, Error> getTotpAt(
      const char *base32EncodedSecret,
      long long time,
      DigitsCount digits=gDefaultDigits,
      Period period=gDefaultPeriod,
      SHA shaAlgo=SHA::SHA1);
  /*!
   * \brief totpToInt
   * \param otp
   * \return
   *
   * \callgraph
   */
  std::expected<int64_t, Error>  totpToInt(const std::string& otp);
}
