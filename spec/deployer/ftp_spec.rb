require 'spec_helper'

describe Wordmove::Deployer::FTP do
  let(:cli_options) do
    {
      config: movefile_path_for('multi_environments'),
      environment: 'production'
    }
  end
  let(:copier) { double(:copier) }
  subject(:deployer) { Wordmove::Deployer::Base.deployer_for(cli_options) }

  before do
    allow(copier).to receive(:logger=)
    allow(Photocopier::FTP).to receive(:new).and_return(copier)
  end

  describe "remote cleanup" do
    before do
      allow(deployer).to receive(:remote_put)
      allow(deployer).to receive(:remote_delete)
      allow(deployer).to receive(:generate_dump_script).and_return("<?php")
      allow(deployer).to receive(:generate_import_script).and_return("<?php")
    end

    it "removes remote dump artifacts even when download_remote_db fails" do
      allow(deployer).to receive(:download).and_raise("boom")

      expect do
        deployer.send(:download_remote_db, "/tmp/dump.sql")
      end.to raise_error(RuntimeError, "boom")

      expect(deployer).to have_received(:remote_delete).with(deployer.send(:remote_wp_content_dir).path("dump.php"))
      expect(deployer).to have_received(:remote_delete).with(deployer.send(:remote_wp_content_dir).path("dump.mysql"))
    end

    it "removes the remote import script even when import_remote_dump fails" do
      allow(deployer).to receive(:download).and_raise("boom")

      expect do
        deployer.send(:import_remote_dump)
      end.to raise_error(RuntimeError, "boom")

      expect(deployer).to have_received(:remote_delete).with(deployer.send(:remote_wp_content_dir).path("import.php"))
    end
  end
end
