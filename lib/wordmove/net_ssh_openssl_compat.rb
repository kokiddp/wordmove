begin
  require 'net/ssh/transport/openssl'
rescue LoadError
  # net-ssh is a transitive dependency of photocopier and may be unavailable
  # while the gemspec is being evaluated.
end

module Wordmove
  module NetSSHOpenSSLCompat
    def self.apply!
      return unless defined?(::OpenSSL::PKey::EC)

      compat = Module.new do
        def read_keyblob(curve_name_in_type, buffer)
          curve_name_in_key = buffer.read_string

          unless curve_name_in_type == curve_name_in_key
            raise Net::SSH::Exception,
                  "curve name mismatched (`#{curve_name_in_key}' with `#{curve_name_in_type}')"
          end

          public_key_oct = buffer.read_string

          begin
            curve_name = ::OpenSSL::PKey::EC::CurveNameAlias[curve_name_in_key]
            group = ::OpenSSL::PKey::EC::Group.new(curve_name)
            point = ::OpenSSL::PKey::EC::Point.new(group, ::OpenSSL::BN.new(public_key_oct, 2))
            asn1 = ::OpenSSL::ASN1::Sequence(
              [
                ::OpenSSL::ASN1::Sequence(
                  [
                    ::OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                    ::OpenSSL::ASN1::ObjectId(curve_name)
                  ]
                ),
                ::OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
              ]
            )

            ::OpenSSL::PKey::EC.new(asn1.to_der)
          rescue ::OpenSSL::PKey::ECError
            raise NotImplementedError, "unsupported key type `#{curve_name_in_type}'"
          end
        end
      end

      eigenclass = class << ::OpenSSL::PKey::EC
        self
      end

      eigenclass.prepend(compat)
    end
  end
end

Wordmove::NetSSHOpenSSLCompat.apply!
