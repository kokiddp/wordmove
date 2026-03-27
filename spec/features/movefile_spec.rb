describe Wordmove::Generators::Movefile do
  let(:movefile) { 'movefile.yml' }
  let(:tmpdir) { "/tmp/wordmove" }

  before do
    @pwd = Dir.pwd
    FileUtils.mkdir(tmpdir)
    Dir.chdir(tmpdir)
  end

  after do
    Dir.chdir(@pwd)
    FileUtils.rm_rf(tmpdir)
  end

  context "::start" do
    before do
      silence_stream(STDOUT) { Wordmove::Generators::Movefile.start }
    end

    it 'creates a Movefile' do
      expect(File.exist?(movefile)).to be true
    end

    it 'fills local wordpress_path using shell path' do
      yaml = YAML.safe_load(ERB.new(File.read(movefile)).result)
      expect(yaml['local']['wordpress_path']).to eq(Dir.pwd)
    end

    it 'fills database configuration defaults' do
      yaml = YAML.safe_load(ERB.new(File.read(movefile)).result)
      expect(yaml['local']['database']['name']).to eq('database_name')
      expect(yaml['local']['database']['user']).to eq('user')
      expect(yaml['local']['database']['password']).to eq('password')
      expect(yaml['local']['database']['host']).to eq('127.0.0.1')
    end

    it 'keeps port commented by default in the generated movefile' do
      content = File.read(movefile)

      expect(content).to include('# port: 3306')
      expect(content).not_to include("\n    port:")
    end

    it 'keeps socket commented by default in the generated movefile' do
      content = File.read(movefile)

      expect(content).to include('# socket: /path/to/mysql.sock # optional unix socket path')
      expect(content).not_to include("\n    socket:")
    end

    it 'creates a Movifile having a "global.sql_adapter" key' do
      yaml = YAML.safe_load(ERB.new(File.read(movefile)).result)
      expect(yaml['global']).to be_present
      expect(yaml['global']['sql_adapter']).to be_present
      expect(yaml['global']['sql_adapter']).to eq('wpcli')
    end
  end

  context "database configuration" do
    let(:wp_config) { File.join(File.dirname(__FILE__), "../fixtures/wp-config.php") }

    before do
      FileUtils.cp(wp_config, ".")
      silence_stream(STDOUT) { Wordmove::Generators::Movefile.start }
    end

    it 'fills database configuration from wp-config' do
      yaml = YAML.safe_load(ERB.new(File.read(movefile)).result)
      expect(yaml['local']['database']['name']).to eq('wordmove_db')
      expect(yaml['local']['database']['user']).to eq('wordmove_user')
      expect(yaml['local']['database']['password']).to eq('wordmove_password')
      expect(yaml['local']['database']['host']).to eq('wordmove_host')
    end
  end

  context "database configuration with unix socket in wp-config" do
    let(:wp_config_content) do
      <<~PHP
        <?php
        define('DB_NAME', 'local');
        define('DB_USER', 'root');
        define('DB_PASSWORD', 'root');
        define('DB_HOST', 'localhost:/tmp/mysql.sock');
      PHP
    end

    before do
      File.write("wp-config.php", wp_config_content)
      silence_stream(STDOUT) { Wordmove::Generators::Movefile.start }
    end

    it "splits DB_HOST into host and socket fields" do
      yaml = YAML.safe_load(ERB.new(File.read(movefile)).result)

      expect(yaml['local']['database']['host']).to eq('localhost')
      expect(yaml['local']['database']['socket']).to eq('/tmp/mysql.sock')
    end

    it "uncomments the local socket line when a socket is detected" do
      content = File.read(movefile)

      expect(content).to include(%(    socket: "/tmp/mysql.sock" # optional unix socket path))
      expect(content).not_to include('# socket: /path/to/mysql.sock # optional unix socket path')
    end
  end

  context "database configuration with custom port in wp-config" do
    let(:wp_config_content) do
      <<~PHP
        <?php
        define('DB_NAME', 'local');
        define('DB_USER', 'root');
        define('DB_PASSWORD', 'root');
        define('DB_HOST', 'localhost:3307');
      PHP
    end

    before do
      File.write("wp-config.php", wp_config_content)
      silence_stream(STDOUT) { Wordmove::Generators::Movefile.start }
    end

    it "splits DB_HOST into host and port fields" do
      yaml = YAML.safe_load(ERB.new(File.read(movefile)).result)

      expect(yaml['local']['database']['host']).to eq('localhost')
      expect(yaml['local']['database']['port']).to eq(3307)
    end

    it "uncomments the local port line when a custom port is detected" do
      content = File.read(movefile)

      expect(content).to include("    port: 3307")
      expect(content).not_to include('# port: 3306')
    end
  end
end
