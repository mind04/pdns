/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>

inline std::string pdns_sha1sum(const std::string& input)
{
  unsigned char result[20] = {0};
  SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha256sum(const std::string& input)
{
  unsigned char result[32] = {0};
  SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha384sum(const std::string& input)
{
  unsigned char result[48] = {0};
  SHA384(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha512sum(const std::string& input)
{
  unsigned char result[64] = {0};
  SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}


class pdns_SHA
{
protected:
  pdns_SHA(const EVP_MD *m) : md(m) {
#if defined(HAVE_EVP_MD_CTX_NEW) && defined(HAVE_EVP_MD_CTX_FREE)
    mdctx = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#else
    mdctx = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#endif
    if (!mdctx) {
      throw std::runtime_error(std::string(EVP_MD_name(md)) + " EVP context initialization failed");
    }
    this->clear();
  }
public:
  void clear() {
    if (EVP_DigestInit_ex(mdctx.get(), md, nullptr) != 1) {
      throw std::runtime_error(std::string(EVP_MD_name(md)) + " EVP digest init failed");
    }
  }
  void update(const std::string& input) {
    if (EVP_DigestUpdate(mdctx.get(), input.data(), input.size()) != 1) {
      throw std::runtime_error(std::string(EVP_MD_name(md)) + " EVP digest update failed");
    }
  }
  std::string hash() {
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
#if defined(HAVE_EVP_MD_CTX_NEW) && defined(HAVE_EVP_MD_CTX_FREE)
    auto mdout = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#else
    auto mdout = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#endif
    if (!mdout) {
      throw std::runtime_error(std::string(EVP_MD_name(md)) + " EVP context new failed");
    }
    if (EVP_MD_CTX_copy_ex(mdout.get(), mdctx.get()) != 1) {
      throw std::runtime_error(std::string(EVP_MD_name(md)) + " EVP context copy failed");
    }
    if (EVP_DigestFinal_ex(mdout.get(), md_value, &md_len) != 1) {
      throw std::runtime_error(std::string(EVP_MD_name(md)) + " EVP digest final failed");
    }
    return std::string(md_value, md_value + md_len);
  }
private:
  const EVP_MD *md;
  std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> mdctx{nullptr,nullptr};
};

class pdns_SHA1 : public pdns_SHA {
public:
  pdns_SHA1() : pdns_SHA(EVP_sha1()) {}
};

class pdns_SHA224 : public pdns_SHA {
public:
  pdns_SHA224() : pdns_SHA(EVP_sha224()) {}
};

class pdns_SHA256 : public pdns_SHA {
public:
  pdns_SHA256() : pdns_SHA(EVP_sha256()) {}
};

class pdns_SHA384 : public pdns_SHA {
public:
  pdns_SHA384() : pdns_SHA(EVP_sha384()) {}
};

class pdns_SHA512 : public pdns_SHA {
public:
  pdns_SHA512() : pdns_SHA(EVP_sha512()) {}
};
