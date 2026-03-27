describe Wordmove::Doctor::Wpcli do
  subject(:doctor) { described_class.new }

  let(:logger) { double("logger", task: nil, success: nil, error: nil) }

  before do
    allow(logger).to receive(:level=)
    allow(Logger).to receive(:new).and_return(logger)
  end

  it "responds to #check!" do
    expect(doctor).to respond_to(:check!)
  end

  context "when wp-cli is installed and up to date" do
    before do
      allow(doctor).to receive(:in_path?).and_return(true)
      allow(doctor).to receive(:`).with("wp cli check-update --format=json --allow-root").and_return("")
    end

    it "checks updates using allow-root" do
      doctor.check!

      expect(logger).to have_received(:success).with("wp-cli is correctly installed")
      expect(logger).to have_received(:success).with("wp-cli is up to date")
    end
  end
end
