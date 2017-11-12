/*
* X.509 Certificates
* (C) 1999-2010,2015,2017 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509cert.h>
#include <botan/pk_keys.h>
#include <botan/x509_ext.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/bigint.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <algorithm>
#include <sstream>

namespace Botan {

/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(DataSource& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE")
   {
   do_decode();
   }

/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(const std::vector<uint8_t>& in) :
   X509_Object(in, "CERTIFICATE/X509 CERTIFICATE")
   {
   do_decode();
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* X509_Certificate Constructor
*/
X509_Certificate::X509_Certificate(const std::string& fsname) :
   X509_Object(fsname, "CERTIFICATE/X509 CERTIFICATE")
   {
   do_decode();
   }
#endif

/*
* Decode the TBSCertificate data
*/
void X509_Certificate::force_decode()
   {
   BER_Decoder tbs_cert(signed_body());
   BigInt serial_bn;

   tbs_cert.decode_optional(m_version, ASN1_Tag(0),
                            ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      .decode(serial_bn)
      .decode(m_sig_algo_inner)
      .decode(m_issuer_dn)
      .start_cons(SEQUENCE)
         .decode(m_not_before)
         .decode(m_not_after)
      .end_cons()
      .decode(m_subject_dn);

   if(m_version > 2)
      throw Decoding_Error("Unknown X.509 cert version " + std::to_string(m_version));
   if(signature_algorithm() != m_sig_algo_inner)
      throw Decoding_Error("X.509 Certificate had differing algorithm identifers in inner and outer ID fields");

   // for general sanity convert wire version (0 based) to standards version (v1 .. v3)
   m_version += 1;

   m_serial = BigInt::encode(serial_bn);
   m_subject_dn_bits = ASN1::put_in_sequence(m_subject_dn.get_bits());
   m_issuer_dn_bits = ASN1::put_in_sequence(m_issuer_dn.get_bits());

   BER_Object public_key = tbs_cert.get_next_object();
   if(public_key.type_tag != SEQUENCE || public_key.class_tag != CONSTRUCTED)
      throw BER_Bad_Tag("X509_Certificate: Unexpected tag for public key",
                        public_key.type_tag, public_key.class_tag);

   // validate_public_key_params(public_key.value);
   AlgorithmIdentifier public_key_alg_id;
   BER_Decoder(public_key.value).decode(public_key_alg_id).discard_remaining();

   std::vector<std::string> public_key_info =
      split_on(OIDS::oid2str(public_key_alg_id.oid), '/');

   if(!public_key_info.empty() && public_key_info[0] == "RSA")
      {
      // RFC4055: If PublicKeyAlgo = PSS or OAEP: limit the use of the public key exclusively to either RSASSA - PSS or RSAES - OAEP
      if(public_key_info.size() >= 2)
         {
         if(public_key_info[1] == "EMSA4")
            {
            /*
            When the RSA private key owner wishes to limit the use of the public
            key exclusively to RSASSA-PSS, then the id-RSASSA-PSS object
            identifier MUST be used in the algorithm field within the subject
            public key information, and, if present, the parameters field MUST
            contain RSASSA-PSS-params.

            All parameters in the signature structure algorithm identifier MUST
            match the parameters in the key structure algorithm identifier
            except the saltLength field. The saltLength field in the signature parameters
            MUST be greater or equal to that in the key parameters field.

            ToDo: Allow salt length to be greater
            */
            if(public_key_alg_id != signature_algorithm())
               {
               throw Decoding_Error("Algorithm identifier mismatch");
               }
            }
         if(public_key_info[1] == "OAEP")
            {
            throw Decoding_Error("Decoding subject public keys of type RSAES-OAEP is currently not supported");
            }
         }
      else
         {
         // oid = rsaEncryption -> parameters field MUST contain NULL
         if(public_key_alg_id != AlgorithmIdentifier(public_key_alg_id.oid, AlgorithmIdentifier::USE_NULL_PARAM))
            {
            throw Decoding_Error("Parameters field MUST contain NULL");
            }
         }
      }

   m_subject_public_key_bits = unlock(public_key.value);

   BER_Decoder(m_subject_public_key_bits)
      .decode(m_subject_public_key_algid)
      .decode(m_subject_public_key_bitstring, BIT_STRING);

   tbs_cert.decode_optional_string(m_v2_issuer_key_id, BIT_STRING, 1);
   tbs_cert.decode_optional_string(m_v2_subject_key_id, BIT_STRING, 2);

   BER_Object v3_exts_data = tbs_cert.get_next_object();
   if(v3_exts_data.type_tag == 3 &&
      v3_exts_data.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder(v3_exts_data.value).decode(m_v3_extensions).verify_end();
      }
   else if(v3_exts_data.type_tag != NO_OBJECT)
      throw BER_Bad_Tag("Unknown tag in X.509 cert",
                        v3_exts_data.type_tag, v3_exts_data.class_tag);

   if(tbs_cert.more_items())
      throw Decoding_Error("TBSCertificate has extra data after extensions block");

   // Now cache some fields from the extensions
   if(auto ext = v3_extensions().get_extension_object_as<Cert_Extension::Key_Usage>())
      {
      m_key_constraints = ext->get_constraints();
      }
   else
      {
      m_key_constraints = NO_CONSTRAINTS;
      }

   if(auto ext = v3_extensions().get_extension_object_as<Cert_Extension::Subject_Key_ID>())
      {
      m_subject_key_id = ext->get_key_id();
      }

   if(auto ext = v3_extensions().get_extension_object_as<Cert_Extension::Authority_Key_ID>())
      {
      m_authority_key_id = ext->get_key_id();
      }

   if(auto ext = v3_extensions().get_extension_object_as<Cert_Extension::Basic_Constraints>())
      {
      if(ext->get_is_ca() == true)
         {
         m_is_ca_certificate = allowed_usage(KEY_CERT_SIGN);

         if(m_is_ca_certificate)
            {
            m_path_len_constraint = ext->get_path_limit();
            }
         }
      }

   if(auto ext = v3_extensions().get_extension_object_as<Cert_Extension::Extended_Key_Usage>())
      {
      m_extended_key_usage = ext->get_oids();
      }

   // Check for self-signed vs self-issued certificates
   if(m_subject_dn == m_issuer_dn)
      {
      std::unique_ptr<Public_Key> pub_key(subject_public_key());
      m_self_signed = check_signature(*pub_key);
      }

   std::unique_ptr<HashFunction> sha1(HashFunction::create("SHA-1"));
   if(sha1)
      {
      sha1->update(m_subject_public_key_bitstring);
      m_subject_public_key_bitstring_sha1 = sha1->final_stdvec();
      // otherwise left as empty, and we will throw if subject_public_key_bitstring_sha1 is called
      }

   m_subject_ds.add(m_subject_dn.contents());
   m_issuer_ds.add(m_issuer_dn.contents());
   v3_extensions().contents_to(m_subject_ds, m_issuer_ds);
   }

/*
* Return the X.509 version in use
*/
uint32_t X509_Certificate::x509_version() const
   {
   return m_version;
   }

bool X509_Certificate::is_self_signed() const
   {
   return m_self_signed;
   }

const X509_Time& X509_Certificate::not_before() const
   {
   return m_not_before;
   }

const X509_Time& X509_Certificate::not_after() const
   {
   return m_not_after;
   }

std::vector<uint8_t> X509_Certificate::v2_issuer_key_id() const
   {
   return m_v2_issuer_key_id;
   }

std::vector<uint8_t> X509_Certificate::v2_subject_key_id() const
   {
   return m_v2_subject_key_id;
   }

/*
* Return information about the subject
*/
std::vector<std::string>
X509_Certificate::subject_info(const std::string& what) const
   {
   const std::string req = X509_DN::deref_info_field(what);
   if(req == "X509.Certificate.v2.key_id")
      return {hex_encode(this->v2_subject_key_id())};
   if(req == "X509v3.SubjectKeyIdentifier")
      return {hex_encode(this->subject_key_id())};
   if(req == "X509.Certificate.dn_bits")
      return {hex_encode(this->raw_subject_dn())};
   if(req == "X509.Certificate.start")
      return {m_not_before.to_string()};
   if(req == "X509.Certificate.end")
      return {m_not_after.to_string()};

   if(req == "X509.Certificate.version")
      return {std::to_string(m_version)};
   if(req == "X509.Certificate.serial")
      return {hex_encode(m_serial)};
   if(req == "X509.Certificate.serial")
      return {hex_encode(m_serial)};

   return m_subject_ds.get(req);
   }

/*
* Return information about the issuer
*/
std::vector<std::string>
X509_Certificate::issuer_info(const std::string& what) const
   {
   const std::string req = X509_DN::deref_info_field(what);
   if(req == "X509.Certificate.v2.key_id")
      return {hex_encode(this->v2_issuer_key_id())};
   if(req == "X509v3.AuthorityKeyIdentifier")
      return {hex_encode(this->authority_key_id())};
   if(req == "X509.Certificate.dn_bits")
      return {hex_encode(this->raw_issuer_dn())};
   if(req == "X509.Certificate.public_key")
      return {hex_encode(this->subject_key_id())};

   return m_issuer_ds.get(req);
   }

/*
* Return the public key in this certificate
*/
std::unique_ptr<Public_Key> X509_Certificate::load_subject_public_key() const
   {
   try
      {
      return std::unique_ptr<Public_Key>(X509::load_key(ASN1::put_in_sequence(this->subject_public_key_bits())));
      }
   catch(std::exception& e)
      {
      throw Decoding_Error("X509_Certificate::load_subject_public_key", e.what());
      }
   }

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bits() const
   {
   return m_subject_public_key_bits;
   }

const std::vector<uint8_t>& X509_Certificate::subject_public_key_bitstring() const
   {
   return m_subject_public_key_bitstring;
   }

std::vector<uint8_t> X509_Certificate::subject_public_key_bitstring_sha1() const
   {
   if(m_subject_public_key_bitstring_sha1.empty())
         throw Encoding_Error("X509_Certificate::subject_public_key_bitstring_sha1 called but SHA-1 disabled in build");

   return m_subject_public_key_bitstring_sha1;
   }

bool X509_Certificate::is_CA_cert() const
   {
   return m_is_ca_certificate;
   }

bool X509_Certificate::allowed_usage(Key_Constraints usage) const
   {
   if(constraints() == NO_CONSTRAINTS)
      return true;
   return ((constraints() & usage) == usage);
   }

bool X509_Certificate::allowed_extended_usage(const std::string& usage) const
   {
   return allowed_extended_usage(OIDS::str2oid(usage));
   }

bool X509_Certificate::allowed_extended_usage(const OID& usage) const
   {
   const std::vector<OID>& ex = extended_key_usage();
   if(ex.empty())
      return true;

   if(std::find(ex.begin(), ex.end(), usage) != ex.end())
      return true;

   return false;
   }

bool X509_Certificate::allowed_usage(Usage_Type usage) const
   {
   // These follow suggestions in RFC 5280 4.2.1.12

   switch(usage)
      {
      case Usage_Type::UNSPECIFIED:
         return true;

      case Usage_Type::TLS_SERVER_AUTH:
         return (allowed_usage(KEY_AGREEMENT) || allowed_usage(KEY_ENCIPHERMENT) || allowed_usage(DIGITAL_SIGNATURE)) && allowed_extended_usage("PKIX.ServerAuth");

      case Usage_Type::TLS_CLIENT_AUTH:
         return (allowed_usage(DIGITAL_SIGNATURE) || allowed_usage(KEY_AGREEMENT)) && allowed_extended_usage("PKIX.ClientAuth");

      case Usage_Type::OCSP_RESPONDER:
         return (allowed_usage(DIGITAL_SIGNATURE) || allowed_usage(NON_REPUDIATION)) && allowed_extended_usage("PKIX.OCSPSigning");

      case Usage_Type::CERTIFICATE_AUTHORITY:
         return is_CA_cert();
      }

   return false;
   }

bool X509_Certificate::has_constraints(Key_Constraints constraints) const
   {
   if(this->constraints() == NO_CONSTRAINTS)
      {
      return false;
      }

   return ((this->constraints() & constraints) != 0);
   }

bool X509_Certificate::has_ex_constraint(const std::string& ex_constraint) const
   {
   return has_ex_constraint(OIDS::str2oid(ex_constraint));
   }

bool X509_Certificate::has_ex_constraint(const OID& usage) const
   {
   const std::vector<OID>& ex = extended_key_usage();
   return (std::find(ex.begin(), ex.end(), usage) != ex.end());
   }

/*
* Return the path length constraint
*/
uint32_t X509_Certificate::path_limit() const
   {
   return m_path_len_constraint;
   }

/*
* Return if a certificate extension is marked critical
*/
bool X509_Certificate::is_critical(const std::string& ex_name) const
   {
   return v3_extensions().critical_extension_set(OIDS::str2oid(ex_name));
   }

/*
* Return the key usage constraints
*/
Key_Constraints X509_Certificate::constraints() const
   {
   return m_key_constraints;
   }

const std::vector<OID>& X509_Certificate::extended_key_usage() const
   {
   return m_extended_key_usage;
   }

std::vector<OID> X509_Certificate::certificate_policy_oids() const
   {
   if(auto ext = v3_extensions().get_extension_object_as<Cert_Extension::Certificate_Policies>())
      {
      return ext->get_policy_oids();
      }
   return std::vector<OID>();
   }

/*
* Return the name constraints
*/
NameConstraints X509_Certificate::name_constraints() const
   {
   if(auto ext = v3_extensions().get_extension_object_as<Cert_Extension::Name_Constraints>())
      {
      return ext->get_name_constraints();
      }
   return NameConstraints(); // no constraints
   }

namespace {

/*
* Lookup each OID in the vector
*/
std::vector<std::string> lookup_oids(const std::vector<OID>& oids)
   {
   std::vector<std::string> out;

   for(const OID& oid : oids)
      {
      out.push_back(OIDS::oid2str(oid));
      }
   return out;
   }

}

/*
* Return the list of extended key usage OIDs
*/
std::vector<std::string> X509_Certificate::ex_constraints() const
   {
   return lookup_oids(extended_key_usage());
   }

/*
* Return the list of certificate policies
*/
std::vector<std::string> X509_Certificate::policies() const
   {
   return lookup_oids(certificate_policy_oids());
   }

const Extensions& X509_Certificate::v3_extensions() const
   {
   return m_v3_extensions;
   }

std::string X509_Certificate::ocsp_responder() const
   {
   if(m_ocsp_responders.size() >= 1)
      {
      return m_ocsp_responders[0];
      }
   return "";
   }

std::string X509_Certificate::crl_distribution_point() const
   {
   if(m_crl_distribution_points.size() >= 1)
      {
      return m_crl_distribution_points[0];
      }
   return "";
   }

/*
* Return the authority key id
*/
std::vector<uint8_t> X509_Certificate::authority_key_id() const
   {
   return m_authority_key_id;
   //return m_issuer.get1_memvec("X509v3.AuthorityKeyIdentifier");
   }

/*
* Return the subject key id
*/
std::vector<uint8_t> X509_Certificate::subject_key_id() const
   {
   return m_subject_key_id;
   }

/*
* Return the certificate serial number
*/
std::vector<uint8_t> X509_Certificate::serial_number() const
   {
   return m_serial;
   }

const X509_DN& X509_Certificate::issuer_dn() const
   {
   return m_issuer_dn;
   }

const X509_DN& X509_Certificate::subject_dn() const
   {
   return m_subject_dn;
   }

std::vector<uint8_t> X509_Certificate::raw_issuer_dn_sha256() const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
   hash->update(raw_issuer_dn());
   return hash->final_stdvec();
   }

std::vector<uint8_t> X509_Certificate::raw_issuer_dn() const
   {
   return m_issuer_dn_bits;
   }

std::vector<uint8_t> X509_Certificate::raw_subject_dn() const
   {
   return m_subject_dn_bits;
   }

std::vector<uint8_t> X509_Certificate::raw_subject_dn_sha256() const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));
   hash->update(raw_subject_dn());
   return hash->final_stdvec();
   }

std::string X509_Certificate::fingerprint(const std::string& hash_name) const
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create(hash_name));
   hash->update(this->BER_encode());
   const std::string hex_print = hex_encode(hash->final());

   std::string formatted_print;

   for(size_t i = 0; i != hex_print.size(); i += 2)
      {
      formatted_print.push_back(hex_print[i]);
      formatted_print.push_back(hex_print[i+1]);

      if(i != hex_print.size() - 2)
         formatted_print.push_back(':');
      }

   return formatted_print;
   }

bool X509_Certificate::matches_dns_name(const std::string& name) const
   {
   if(name.empty())
      return false;

   std::vector<std::string> issued_names = subject_info("DNS");

   // Fall back to CN only if no DNS names are set (RFC 6125 sec 6.4.4)
   if(issued_names.empty())
      issued_names = subject_info("Name");

   for(size_t i = 0; i != issued_names.size(); ++i)
      {
      if(host_wildcard_match(issued_names[i], name))
         return true;
      }

   return false;
   }

/*
* Compare two certificates for equality
*/
bool X509_Certificate::operator==(const X509_Certificate& other) const
   {
   return (this->signature() == other.signature() &&
           this->signature_algorithm() == other.signature_algorithm() &&
           this->signed_body() == other.signed_body());
   }

bool X509_Certificate::operator<(const X509_Certificate& other) const
   {
   /* If signature values are not equal, sort by lexicographic ordering of that */
   if(this->signature() != other.signature())
      {
      return (this->signature() < other.signature());
      }

   // Then compare the signed contents
   return this->signed_body() < other.signed_body();
   }

/*
* X.509 Certificate Comparison
*/
bool operator!=(const X509_Certificate& cert1, const X509_Certificate& cert2)
   {
   return !(cert1 == cert2);
   }

std::string X509_Certificate::to_string() const
   {
   const std::vector<std::string> dn_fields{
      "Name",
      "Email",
      "Organization",
      "Organizational Unit",
      "Locality",
      "State",
      "Country",
      "IP",
      "DNS",
      "URI",
      "PKIX.XMPPAddr"
      };

   std::ostringstream out;

   for(auto&& field : dn_fields)
      {
      for(auto&& val : subject_info(field))
         {
         out << "Subject " << field << ": " << val << "\n";
         }
      }

   for(auto&& field : dn_fields)
      {
      for(auto&& val : issuer_info(field))
         {
         out << "Issuer " << field << ": " << val << "\n";
         }
      }

   out << "Version: " << this->x509_version() << "\n";

   out << "Not valid before: " << this->not_before().to_string() << "\n";
   out << "Not valid after: " << this->not_after().to_string() << "\n";

   out << "Constraints:\n";
   Key_Constraints constraints = this->constraints();
   if(constraints == NO_CONSTRAINTS)
      out << " None\n";
   else
      {
      if(constraints & DIGITAL_SIGNATURE)
         out << "   Digital Signature\n";
      if(constraints & NON_REPUDIATION)
         out << "   Non-Repudiation\n";
      if(constraints & KEY_ENCIPHERMENT)
         out << "   Key Encipherment\n";
      if(constraints & DATA_ENCIPHERMENT)
         out << "   Data Encipherment\n";
      if(constraints & KEY_AGREEMENT)
         out << "   Key Agreement\n";
      if(constraints & KEY_CERT_SIGN)
         out << "   Cert Sign\n";
      if(constraints & CRL_SIGN)
         out << "   CRL Sign\n";
      if(constraints & ENCIPHER_ONLY)
         out << "   Encipher Only\n";
      if(constraints & DECIPHER_ONLY)
         out << "   Decipher Only\n";
      }

   std::vector<std::string> policies = this->policies();
   if(!policies.empty())
      {
      out << "Policies: " << "\n";
      for(size_t i = 0; i != policies.size(); i++)
         out << "   " << policies[i] << "\n";
      }

   std::vector<OID> ex_constraints = this->extended_key_usage();
   if(!ex_constraints.empty())
      {
      out << "Extended Constraints:\n";
      for(size_t i = 0; i != ex_constraints.size(); i++)
         out << "   " << OIDS::oid2str(ex_constraints[i]) << "\n";
      }

   NameConstraints name_constraints = this->name_constraints();
   if(!name_constraints.permitted().empty() ||
         !name_constraints.excluded().empty())
      {
      out << "Name Constraints:\n";

      if(!name_constraints.permitted().empty())
         {
         out << "   Permit";
         for(auto st: name_constraints.permitted())
            {
            out << " " << st.base();
            }
         out << "\n";
         }

      if(!name_constraints.excluded().empty())
         {
         out << "   Exclude";
         for(auto st: name_constraints.excluded())
            {
            out << " " << st.base();
            }
         out << "\n";
         }
      }

   if(!ocsp_responder().empty())
      out << "OCSP responder " << ocsp_responder() << "\n";
   if(!crl_distribution_point().empty())
      out << "CRL " << crl_distribution_point() << "\n";

   out << "Signature algorithm: " <<
      OIDS::oid2str(this->signature_algorithm().oid) << "\n";

   out << "Serial number: " << hex_encode(this->serial_number()) << "\n";

   if(this->authority_key_id().size())
     out << "Authority keyid: " << hex_encode(this->authority_key_id()) << "\n";

   if(this->subject_key_id().size())
     out << "Subject keyid: " << hex_encode(this->subject_key_id()) << "\n";

   std::unique_ptr<Public_Key> pubkey(this->subject_public_key());
   out << "Public Key:\n" << X509::PEM_encode(*pubkey);

   return out.str();
   }

/*
* Create and populate a X509_DN
*/
X509_DN create_dn(const Data_Store& info)
   {
   auto names = info.search_for(
      [](const std::string& key, const std::string&)
      {
         return (key.find("X520.") != std::string::npos);
      });

   X509_DN dn;

   for(auto i = names.begin(); i != names.end(); ++i)
      dn.add_attribute(i->first, i->second);

   return dn;
   }

/*
* Create and populate an AlternativeName
*/
AlternativeName create_alt_name(const Data_Store& info)
   {
   auto names = info.search_for(
      [](const std::string& key, const std::string&)
      {
         return (key == "RFC822" ||
                 key == "DNS" ||
                 key == "URI" ||
                 key == "IP");
      });

   AlternativeName alt_name;

   for(auto i = names.begin(); i != names.end(); ++i)
      alt_name.add_attribute(i->first, i->second);

   return alt_name;
   }

}
