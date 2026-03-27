require 'spec_helper'

describe Wordmove::Generators::WordpressDBConfig do
  let(:tmpdir) { Dir.mktmpdir("wordmove-wp-config") }
  let(:wp_config_path) { File.join(tmpdir, "wp-config.php") }

  before do
    allow(WordpressDirectory).to receive(:default_path_for).with(:wp_config).and_return(wp_config_path)
  end

  after do
    FileUtils.rm_rf(tmpdir)
  end

  it "parses definitions without swallowing trailing quoted comments" do
    File.write(
      wp_config_path,
      <<~PHP
        <?php
        define('DB_NAME', 'wordmove_db'); // "quoted comment"
        define("DB_USER", "wordmove_user"); // 'another quoted comment'
        define('DB_PASSWORD', 'wordmove_password');
        define('DB_HOST', 'wordmove_host');
      PHP
    )

    config = described_class.new.config

    expect(config[:name]).to eq('wordmove_db')
    expect(config[:user]).to eq('wordmove_user')
    expect(config[:password]).to eq('wordmove_password')
    expect(config[:host]).to eq('wordmove_host')
  end
end

describe Wordmove::Generators::VhostReader do
  let(:tmpdir) { Dir.mktmpdir("wordmove-vhost-reader") }
  let(:wp_config_path) { File.join(tmpdir, "wp-config.php") }
  subject(:reader) { described_class.new }

  before do
    allow(WordpressDirectory).to receive(:default_path_for).with(:wp_config).and_return(wp_config_path)
    allow(Dir).to receive(:pwd).and_return(tmpdir)
  end

  after do
    FileUtils.rm_rf(tmpdir)
  end

  it "reads WP_HOME from wp-config.php" do
    File.write(wp_config_path, "<?php\ndefine('WP_HOME', 'https://local.example.test');\n")

    expect(reader.config).to eq('https://local.example.test')
  end

  it "falls back to WP_SITEURL when WP_HOME is missing" do
    File.write(wp_config_path, "<?php\ndefine('WP_SITEURL', 'https://siteurl.example.test');\n")

    expect(reader.config).to eq('https://siteurl.example.test')
  end

  it "falls back to wp option get home when wp-config has no vhost constants" do
    File.write(wp_config_path, "<?php\ndefine('DB_NAME', 'wordmove');\n")
    allow(reader).to receive(:wp_in_path?).and_return(true)
    allow(reader).to receive(:read_wp_option).with('home').and_return('https://home-from-db.example.test')

    expect(reader.config).to eq('https://home-from-db.example.test')
  end

  it "falls back to siteurl when home is blank" do
    File.write(wp_config_path, "<?php\ndefine('DB_NAME', 'wordmove');\n")
    allow(reader).to receive(:wp_in_path?).and_return(true)
    allow(reader).to receive(:read_wp_option).with('home').and_return('')
    allow(reader).to receive(:read_wp_option).with('siteurl').and_return('https://siteurl-from-db.example.test')

    expect(reader.config).to eq('https://siteurl-from-db.example.test')
  end

  it "keeps the default when neither wp-config nor wp-cli returns a vhost" do
    File.write(wp_config_path, "<?php\ndefine('DB_NAME', 'wordmove');\n")
    allow(reader).to receive(:wp_in_path?).and_return(false)

    expect(reader.config).to eq('http://vhost.local')
  end
end
