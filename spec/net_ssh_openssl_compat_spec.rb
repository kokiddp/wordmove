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
  end
end
