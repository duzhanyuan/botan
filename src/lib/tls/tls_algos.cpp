/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_algos.h>
#include <botan/exceptn.h>

namespace Botan {

namespace TLS {

std::string kdf_algo_to_string(KDF_Algo algo)
   {
   switch(algo)
      {
      case KDF_Algo::SHA_1:
         return "SHA-1";
      case KDF_Algo::SHA_256:
         return "SHA-256";
      case KDF_Algo::SHA_384:
         return "SHA-384";
      }

   throw Invalid_State("kdf_algo_to_string unknown enum value");
   }

std::string kex_method_to_string(Kex_Algo method)
   {
   switch(method)
      {
      case Kex_Algo::STATIC_RSA:
         return "RSA";
      case Kex_Algo::DH:
         return "DH";
      case Kex_Algo::ECDH:
         return "ECDH";
      case Kex_Algo::CECPQ1:
         return "CECPQ1";
      case Kex_Algo::SRP_SHA:
         return "SRP_SHA";
      case Kex_Algo::PSK:
         return "PSK";
      case Kex_Algo::DHE_PSK:
         return "DHE_PSK";
      case Kex_Algo::ECDHE_PSK:
         return "ECDHE_PSK";
      }

   throw Invalid_State("kex_method_to_string unknown enum value");
   }

Kex_Algo kex_method_from_string(const std::string& str)
   {
   if(str == "RSA")
      return Kex_Algo::STATIC_RSA;

   if(str == "DH")
      return Kex_Algo::DH;

   if(str == "ECDH")
      return Kex_Algo::ECDH;

   if(str == "CECPQ1")
      return Kex_Algo::CECPQ1;

   if(str == "SRP_SHA")
      return Kex_Algo::SRP_SHA;

   if(str == "PSK")
      return Kex_Algo::PSK;

   if(str == "DHE_PSK")
      return Kex_Algo::DHE_PSK;

   if(str == "ECDHE_PSK")
      return Kex_Algo::ECDHE_PSK;

   throw Invalid_Argument("Unknown kex method " + str);
   }

std::string auth_method_to_string(Sig_Algo method)
   {
   switch(method)
      {
      case Sig_Algo::RSA:
         return "RSA";
      case Sig_Algo::DSA:
         return "DSA";
      case Sig_Algo::ECDSA:
         return "ECDSA";
      case Sig_Algo::IMPLICIT:
         return "IMPLICIT";
      case Sig_Algo::ANONYMOUS:
         return "ANONYMOUS";
      }

    throw Invalid_State("auth_method_to_string unknown enum value");
   }

Sig_Algo auth_method_from_string(const std::string& str)
   {
   if(str == "RSA")
      return Sig_Algo::RSA;
   if(str == "DSA")
      return Sig_Algo::DSA;
   if(str == "ECDSA")
      return Sig_Algo::ECDSA;
   if(str == "ANONYMOUS" || str == "")
      return Sig_Algo::ANONYMOUS;

   throw Invalid_Argument("Bad signature method " + str);
   }

}

}
