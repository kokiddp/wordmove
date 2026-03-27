require "net/ssh/buffer"

describe Wordmove::NetSSHOpenSSLCompat do
  describe ".apply!" do
    it "builds EC host keys without mutating the pkey" do
      original = OpenSSL::PKey::EC.generate("prime256v1")
      public_key_octets = original.public_key.to_octet_string(:uncompressed)
      buffer = Net::SSH::Buffer.from(:string, "nistp256", :string, public_key_octets)

      key = OpenSSL::PKey::EC.read_keyblob("nistp256", buffer)

      expect(key).to be_a(OpenSSL::PKey::EC)
      expect(key.public_key.to_octet_string(:uncompressed)).to eq(public_key_octets)
    end

    it "builds RSA host keys without mutating the pkey" do
      original = OpenSSL::PKey::RSA.generate(2048)
      buffer = Net::SSH::Buffer.from(:bignum, original.e, :bignum, original.n)

      key = buffer.read_keyblob("ssh-rsa")

      expect(key).to be_a(OpenSSL::PKey::RSA)
      expect(key.n).to eq(original.n)
      expect(key.e).to eq(original.e)
    end

    it "builds ECDH key exchange keys without mutating the pkey" do
      key = Net::SSH::Transport::Kex::EcdhSHA2NistP256.allocate.send(:generate_key)

      expect(key).to be_a(OpenSSL::PKey::EC)
      expect(key.public_key).not_to be_nil
    end

    it "builds DH key exchange keys without mutating the pkey" do
      key = Net::SSH::Transport::Kex::DiffieHellmanGroup1SHA1.allocate.send(:generate_key)

      expect(key).to be_a(OpenSSL::PKey::DH)
      expect(key.pub_key).not_to be_nil
    end
  end
end
