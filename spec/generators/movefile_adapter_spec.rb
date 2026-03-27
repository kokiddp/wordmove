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
