require 'spec_helper'

describe Wordmove::Deployer::Ssh::WpcliSqlAdapter do
  let(:cli_options) do
    {
      config: movefile_path_for('multi_environments_wpcli_sql_adapter'),
      environment: 'staging',
      no_adapt: true
    }
  end
  let(:copier) { double(:copier) }
  subject(:deployer) { Wordmove::Deployer::Base.deployer_for(cli_options) }

  before do
    allow(copier).to receive(:logger=)
    allow(Photocopier::SSH).to receive(:new).and_return(copier)
  end

  describe "no_adapt handling" do
    before do
      allow(deployer).to receive(:run)
      allow(deployer).to receive(:save_local_db)
      allow(deployer).to receive(:download_remote_db)
      allow(deployer).to receive(:import_remote_dump)
      allow(deployer).to receive(:local_delete)
      allow(deployer).to receive(:normalize_collations!)
      allow(deployer).to receive(:compress_command).and_return("gzip -9 -f dump.sql")
      allow(deployer).to receive(:uncompress_command).and_return("gzip -d -f dump.sql.gz")
      allow(deployer).to receive(:mysql_import_command).and_return("mysql < dump.sql")
    end

    it "does not pass nil to run while adapting the local database" do
      expect { deployer.send(:adapt_local_db!) }.not_to raise_error
      expect(deployer).not_to have_received(:run).with(nil)
    end

    it "does not pass nil to run while adapting the remote database" do
      expect { deployer.send(:adapt_remote_db!) }.not_to raise_error
      expect(deployer).not_to have_received(:run).with(nil)
    end
  end
end
