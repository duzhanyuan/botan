/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_ALGO_IDS_H_
#define BOTAN_TLS_ALGO_IDS_H_

#include <botan/types.h>

namespace Botan {

namespace TLS {

enum class Cipher_Algo {
   CHACHA20_POLY1305,

   AES_128_CBC_HMAC_SHA1 = 100,
   AES_128_CBC_HMAC_SHA256,
   AES_128_CCM,
   AES_128_CCM_8,
   AES_128_GCM,
   AES_128_OCB,

   AES_256_CBC_HMAC_SHA1 = 200,
   AES_256_CBC_HMAC_SHA256,
   AES_256_CBC_HMAC_SHA384,
   AES_256_CCM,
   AES_256_CCM_8,
   AES_256_GCM,
   AES_256_OCB,

   CAMELLIA_128_CBC_HMAC_SHA1 = 300,
   CAMELLIA_128_CBC_HMAC_SHA256,
   CAMELLIA_128_GCM,

   CAMELLIA_256_CBC_HMAC_SHA1 = 400,
   CAMELLIA_256_CBC_HMAC_SHA256,
   CAMELLIA_256_CBC_HMAC_SHA384,
   CAMELLIA_256_GCM,

   ARIA_128_GCM = 500,
   ARIA_256_GCM,

   SEED_CBC_HMAC_SHA1 = 1000,
   DES_EDE_CBC_HMAC_SHA1,
};

enum class KDF_Algo {
   SHA_1,
   SHA_256,
   SHA_384,
};

std::string BOTAN_DLL kdf_algo_to_string(KDF_Algo algo);

enum class Nonce_Format {
   CBC_MODE,
   AEAD_IMPLICIT_4,
   AEAD_XOR_12,
};

// TODO encoding should match signature_algorithms extension
// TODO this should include hash etc as in TLS v1.3
enum class Auth_Method {
   RSA,
   DSA,
   ECDSA,

   // These are placed outside the encodable range
   IMPLICIT = 0x10000,
   ANONYMOUS
};

std::string auth_method_to_string(Auth_Method method);
Auth_Method auth_method_from_string(const std::string& str);

enum class Kex_Algo {
   STATIC_RSA,
   DH,
   ECDH,
   CECPQ1,
   SRP_SHA,
   PSK,
   DHE_PSK,
   ECDHE_PSK,
};

std::string kex_method_to_string(Kex_Algo method);
Kex_Algo kex_method_from_string(const std::string& str);

inline bool key_exchange_is_psk(Kex_Algo m)
   {
   return (m == Kex_Algo::PSK ||
           m == Kex_Algo::DHE_PSK ||
           m == Kex_Algo::ECDHE_PSK);
   }

}

}

#endif
