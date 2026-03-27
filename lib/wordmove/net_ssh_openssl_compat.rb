begin
  require 'net/ssh/transport/openssl'
  require 'net/ssh/buffer'
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

      return unless defined?(::Net::SSH::Buffer)

      buffer_compat = Module.new do
        def read_private_keyblob(type)
          case type
          when /^ssh-rsa$/
            n = read_bignum
            e = read_bignum
            d = read_bignum
            iqmp = read_bignum
            p = read_bignum
            q = read_bignum
            _unkown1 = read_bignum
            _unkown2 = read_bignum
            dmp1 = d % (p - 1)
            dmq1 = d % (q - 1)

            data_sequence = ::OpenSSL::ASN1::Sequence([
              ::OpenSSL::ASN1::Integer(n),
              ::OpenSSL::ASN1::Integer(e)
            ])

            if d && p && q && dmp1 && dmq1 && iqmp
              data_sequence = ::OpenSSL::ASN1::Sequence([
                ::OpenSSL::ASN1::Integer(0),
                ::OpenSSL::ASN1::Integer(n),
                ::OpenSSL::ASN1::Integer(e),
                ::OpenSSL::ASN1::Integer(d),
                ::OpenSSL::ASN1::Integer(p),
                ::OpenSSL::ASN1::Integer(q),
                ::OpenSSL::ASN1::Integer(dmp1),
                ::OpenSSL::ASN1::Integer(dmq1),
                ::OpenSSL::ASN1::Integer(iqmp)
              ])
            end

            asn1 = ::OpenSSL::ASN1::Sequence(data_sequence)
            ::OpenSSL::PKey::RSA.new(asn1.to_der)
          else
            super
          end
        end

        def read_keyblob(type)
          case type
          when /^ssh-dss$/
            p = read_bignum
            q = read_bignum
            g = read_bignum
            pub_key = read_bignum

            asn1 = ::OpenSSL::ASN1::Sequence.new(
              [
                ::OpenSSL::ASN1::Sequence.new(
                  [
                    ::OpenSSL::ASN1::ObjectId.new('DSA'),
                    ::OpenSSL::ASN1::Sequence.new(
                      [
                        ::OpenSSL::ASN1::Integer.new(p),
                        ::OpenSSL::ASN1::Integer.new(q),
                        ::OpenSSL::ASN1::Integer.new(g)
                      ]
                    )
                  ]
                ),
                ::OpenSSL::ASN1::BitString.new(::OpenSSL::ASN1::Integer.new(pub_key).to_der)
              ]
            )

            ::OpenSSL::PKey::DSA.new(asn1.to_der)
          when /^ssh-rsa$/
            e = read_bignum
            n = read_bignum

            asn1 = ::OpenSSL::ASN1::Sequence(
              [
                ::OpenSSL::ASN1::Integer(n),
                ::OpenSSL::ASN1::Integer(e)
              ]
            )

            ::OpenSSL::PKey::RSA.new(asn1.to_der)
          else
            super
          end
        end
      end

      ::Net::SSH::Buffer.prepend(buffer_compat)
    end
  end
end

Wordmove::NetSSHOpenSSLCompat.apply!
