describe Wordmove::Logger do
  context "#task_step" do
    let(:logger) { described_class.new(STDOUT) }

    it "prints single-line commands unchanged" do
      expect { logger.task_step(true, 'gzip -9 -f "dump.sql"') }
        .to output(/compress dump\.sql/)
        .to_stdout_from_any_process
    end

    it "summarizes mysqldump commands" do
      command = '$(command -v mariadb-dump >/dev/null 2>&1 && echo mariadb-dump || echo mysqldump) ' \
                '--host=localhost --user=root --password=secret --result-file="./wp-content/dump.sql" my_db'

      expect { logger.task_step(true, command) }
        .to output(/dump database my_db to \.\/wp-content\/dump\.sql/)
        .to_stdout_from_any_process
    end

    it "summarizes wp search-replace commands" do
      command = 'wp search-replace --path=./public old.example.test new.example.test ' \
                '--quiet --skip-columns=guid --all-tables --allow-root'

      expect { logger.task_step(true, command) }
        .to output(/wp search-replace old\.example\.test -> new\.example\.test in \.\/public/)
        .to_stdout_from_any_process
    end

    it "leaves hook exec lines unchanged" do
      expect { logger.task_step(true, 'Exec command: pwd') }
        .to output(/Exec command: pwd/)
        .to_stdout_from_any_process
    end

    it "summarizes multiline mysql import scripts" do
      command = [
        'first_line=$(head -n 1 dump.sql 2>/dev/null || true)',
        'tmp_dump="$(mktemp)"',
        'printf "\\nCOMMIT;\\n" >> "$tmp_dump"',
        'mysql --init-command="SET autocommit=0; SET FOREIGN_KEY_CHECKS=0" < "$tmp_dump"'
      ].join("\n")

      expect { logger.task_step(true, command) }
        .to output(/import SQL dump dump\.sql \(strip sandbox header, append COMMIT\)/)
        .to_stdout_from_any_process
    end

    it "includes the target database in multiline mysql import summaries" do
      command = [
        'first_line=$(head -n 1 ./wp-content/dump.sql 2>/dev/null || true)',
        'tmp_dump="$(mktemp)"',
        'printf "\\nCOMMIT;\\n" >> "$tmp_dump"',
        'mysql --database=local --init-command="SET autocommit=0; SET FOREIGN_KEY_CHECKS=0" < "$tmp_dump"'
      ].join("\n")

      expect { logger.task_step(true, command) }
        .to output(/import SQL dump \.\/wp-content\/dump\.sql into database local \(strip sandbox header, append COMMIT\)/)
        .to_stdout_from_any_process
    end
  end

  context "#info" do
    context "having some string to filter" do
      let(:logger) { described_class.new(STDOUT, ['hidden']) }

      it "will hide the passed strings" do
        expect { logger.info('What I write is hidden') }
          .to output(/What I write is \[secret\]/)
          .to_stdout_from_any_process
      end
    end

    context "having a string with regexp special characters" do
      let(:logger) { described_class.new(STDOUT, ['comp/3xPa((w0r]']) }

      it "will hide the passed strings" do
        expect { logger.info('What I write is comp/3xPa((w0r]') }
          .to output(/What I write is \[secret\]/)
          .to_stdout_from_any_process
      end
    end
  end
end
