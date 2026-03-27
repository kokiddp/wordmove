describe Wordmove::Doctor::Mysql do
  let(:movefile_name) { 'multi_environments' }
  let(:movefile_dir) { "spec/fixtures/movefiles" }
  let(:doctor) { described_class.new(movefile_name, movefile_dir) }

  context ".new" do
    it "implements #check! method" do
      expect_any_instance_of(described_class).to receive(:check!)

      silence_stream(STDOUT) { doctor.check! }
    end

    it "calls mysql client check" do
      expect(doctor).to receive(:mysql_client_doctor)

      silence_stream(STDOUT) { doctor.check! }
    end

    it "calls mysqldump check" do
      expect(doctor).to receive(:mysqldump_doctor)

      silence_stream(STDOUT) { doctor.check! }
    end

    it "calls mysql server check" do
      expect(doctor).to receive(:mysql_server_doctor)

      silence_stream(STDOUT) { doctor.check! }
    end

    it "calls mysql database check" do
      # expect(doctor).to receive(:mysql_database_doctor)

      silence_stream(STDOUT) { doctor.check! }
    end
  end

  context "socket-aware connection commands" do
    it "uses the dedicated socket option in doctor checks" do
      allow(doctor).to receive(:config).and_return(
        host: "localhost",
        user: "root",
        password: "root",
        socket: "/tmp/mysql.sock"
      )

      command = doctor.send(:mysql_command)

      expect(command).to include("--socket=/tmp/mysql.sock")
    end

    it "keeps supporting socket passed through mysql_options" do
      allow(doctor).to receive(:config).and_return(
        host: "localhost",
        user: "root",
        password: "root",
        mysql_options: "--socket /tmp/mysql.sock --protocol=TCP"
      )

      command = doctor.send(:mysql_command)

      expect(command).to include("--socket /tmp/mysql.sock")
      expect(command.scan(/--socket(?:=|\s+)/).size).to eq(1)
    end

    it "falls back to socket found in mysqldump_options" do
      allow(doctor).to receive(:config).and_return(
        host: "localhost",
        user: "root",
        password: "root",
        mysqldump_options: "--socket=/tmp/mysql.sock"
      )

      command = doctor.send(:mysql_command)

      expect(command).to include("--socket=/tmp/mysql.sock")
    end
  end
end
