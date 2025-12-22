require 'tempfile'
require 'fileutils'

module Wordmove
  module Deployer
    class Base
      attr_reader :options
      attr_reader :logger
      attr_reader :environment
      SANDBOX_MAGIC_COMMENT = '/*!999999- enable the sandbox mode */'.freeze

      class << self
        def deployer_for(cli_options)
          movefile = Wordmove::Movefile.new(cli_options[:config])
          movefile.load_dotenv(cli_options)

          options = movefile.fetch.merge! cli_options
          environment = movefile.environment(cli_options)

          # localとenvironmentのdatabaseにoriginを追加
          options[:local][:database][:origin] = 'local'
          options[environment][:database][:origin] = 'remote'

          return FTP.new(environment, options) if options[environment][:ftp]

          if options[environment][:ssh] && options[:global][:sql_adapter] == 'wpcli'
            return Ssh::WpcliSqlAdapter.new(environment, options)
          end

          if options[environment][:ssh] && options[:global][:sql_adapter] == 'default'
            return Ssh::DefaultSqlAdapter.new(environment, options)
          end

          raise NoAdapterFound, "No valid adapter found."
        end

        def current_dir
          '.'
        end

        def logger(secrets)
          Logger.new(STDOUT, secrets).tap { |l| l.level = Logger::DEBUG }
        end
      end

      def initialize(environment, options = {})
        @environment = environment.to_sym
        @options = options

        movefile_secrets = Wordmove::Movefile.new(options[:config]).secrets
        @logger = self.class.logger(movefile_secrets)
      end

      def push_db
        logger.task "Pushing Database"
      end

      def pull_db
        logger.task "Pulling Database"
      end

      def remote_get_directory; end

      def remote_put_directory; end

      def exclude_dir_contents(path)
        "#{path}/*"
      end

      def push_wordpress
        logger.task "Pushing wordpress core"

        local_path = local_options[:wordpress_path]
        remote_path = remote_options[:wordpress_path]
        exclude_wp_content = exclude_dir_contents(local_wp_content_dir.relative_path)
        exclude_paths = paths_to_exclude.push(exclude_wp_content)

        remote_put_directory(local_path, remote_path, exclude_paths)
      end

      def pull_wordpress
        logger.task "Pulling wordpress core"

        local_path = local_options[:wordpress_path]
        remote_path = remote_options[:wordpress_path]
        exclude_wp_content = exclude_dir_contents(remote_wp_content_dir.relative_path)
        exclude_paths = paths_to_exclude.push(exclude_wp_content)

        remote_get_directory(remote_path, local_path, exclude_paths)
      end

      protected

      def paths_to_exclude
        remote_options[:exclude] || []
      end

      def run(command)
        logger.task_step true, command
        return true if simulate?

        system(command)
        raise ShellCommandError, "Return code reports an error" unless $CHILD_STATUS.success?
      end

      def download(url, local_path)
        logger.task_step true, "download #{url} > #{local_path}"

        return true if simulate?

        File.open(local_path, 'w') do |file|
          file << URI.open(url).read
        end
      end

      def simulate?
        options[:simulate]
      end

      [
        WordpressDirectory::Path::WP_CONTENT,
        WordpressDirectory::Path::PLUGINS,
        WordpressDirectory::Path::MU_PLUGINS,
        WordpressDirectory::Path::THEMES,
        WordpressDirectory::Path::UPLOADS,
        WordpressDirectory::Path::LANGUAGES
      ].each do |type|
        %i[remote local].each do |location|
          define_method "#{location}_#{type}_dir" do
            options = send("#{location}_options")
            WordpressDirectory.new(type, options)
          end
        end
      end

      def mysql_dump_command(options, save_to_path)
        command = [mysql_dump_binary]
        command << "--host=#{Shellwords.escape(options[:host])}" if options[:host].present?
        command << "--port=#{Shellwords.escape(options[:port])}" if options[:port].present?
        command << "--user=#{Shellwords.escape(options[:user])}" if options[:user].present?
        if options[:password].present?
          command << "--password=#{Shellwords.escape(options[:password])}"
        end
        command << "--result-file=\"#{save_to_path}\""
        if options[:mysqldump_options].present?
          command << Shellwords.split(options[:mysqldump_options])
        end
        command << Shellwords.escape(options[:name])
        command.join(" ")
      end

      def mysql_import_command(dump_path, options)
        mysql_command = mysql_client_command(options, import: true)
        escaped_dump_path = Shellwords.escape(dump_path)

        init_commands = [
          "SET autocommit=0",
          "SET FOREIGN_KEY_CHECKS=0"
        ].join('; ')

        [
          "first_line=$(head -n 1 #{escaped_dump_path} 2>/dev/null || true)",
          'tmp_dump="$(mktemp)"',
          %{if [ "$first_line" = '#{SANDBOX_MAGIC_COMMENT}' ]; then},
          "tail -n +2 #{escaped_dump_path} > \"$tmp_dump\"",
          'else',
          "cat #{escaped_dump_path} > \"$tmp_dump\"",
          'fi',
          'printf "\\\\nCOMMIT;\\\\n" >> "$tmp_dump"',
          "#{mysql_command} --init-command=\"#{init_commands}\" < \"$tmp_dump\"",
          'import_status=$?',
          'rm -f "$tmp_dump"',
          'exit $import_status'
        ].join("\n")
      end

      def compress_command(path)
        command = ["gzip"]
        command << "-9"
        command << "-f"
        command << "\"#{path}\""
        command.join(" ")
      end

      def uncompress_command(path)
        command = ["gzip"]
        command << "-d"
        command << "-f"
        command << "\"#{path}\""
        command.join(" ")
      end

      def local_delete(path)
        logger.task_step true, "delete: '#{path}'"
        File.delete(path) unless simulate?
      end

      def save_local_db(local_dump_path)
        # dump local mysql into file
        run mysql_dump_command(local_options[:database], local_dump_path)
      end

      def remote_options
        options[environment].clone
      end

      def local_options
        options[:local].clone
      end

      def mysql_client_binary
        '$(command -v mariadb >/dev/null 2>&1 && echo mariadb || echo mysql)'
      end

      def mysql_dump_binary
        '$(command -v mariadb-dump >/dev/null 2>&1 && echo mariadb-dump || echo mysqldump)'
      end

      def mysql_client_command(options, import: false)
        mysql_options = options[:mysql_options]
        command = [mysql_client_binary]
        command << "--host=#{Shellwords.escape(options[:host])}" if options[:host].present?
        command << "--port=#{Shellwords.escape(options[:port])}" if options[:port].present?
        command << "--user=#{Shellwords.escape(options[:user])}" if options[:user].present?
        if options[:password].present?
          command << "--password=#{Shellwords.escape(options[:password])}"
        end
        command << "--database=#{Shellwords.escape(options[:name])}"
        command << "--force" if import
        unless mysql_options.to_s.match?(/--(?:skip-)?binary-mode\b/)
          command << "--binary-mode" if import
        end
        command << Shellwords.split(mysql_options) if mysql_options.present?
        command.join(" ")
      end

      def normalize_collations!(dump_path)
        return if simulate?

        mappings = collation_fallbacks
        charset_map = charset_fallbacks
        return if mappings.empty? && charset_map.empty?

        temp_dump = Tempfile.new(['wordmove-collation', '.sql'])
        begin
          File.open(dump_path, 'rb') do |input|
            File.open(temp_dump.path, 'wb') do |output|
              input.each_line do |line|
                # Ensure we do not explode on invalid byte sequences coming from dumps
                safe_line = begin
                  line.force_encoding(Encoding::UTF_8)
                  line.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: '')
                rescue StandardError
                  line.dup.force_encoding(Encoding::UTF_8)
                end

                replaced_collation = false
                mappings.each do |pattern, replacement|
                  next unless safe_line.match?(pattern)

                  if replacement.is_a?(Hash)
                    safe_line = safe_line.gsub(pattern, replacement[:collation])
                    replaced_collation = true
                    if replacement[:charset]
                      safe_line = safe_line.gsub(/utf8mb3\b/, replacement[:charset])
                    end
                  else
                    safe_line = safe_line.gsub(pattern, replacement)
                    replaced_collation = true
                  end
                end

                # If we replaced collations but still see utf8mb3, upgrade charset to avoid mismatches
                if replaced_collation
                  charset_map.each do |pattern, replacement|
                    safe_line = safe_line.gsub(pattern, replacement)
                  end
                end
                output.write(safe_line)
              end
            end
          end

          FileUtils.mv(temp_dump.path, dump_path)
        ensure
          temp_dump.close!
        end
      end

      def collation_fallbacks
        raw_mappings = options.dig(:global, :collation_fallbacks) || default_collation_fallbacks
        return {} unless raw_mappings

        raw_mappings.each_with_object({}) do |(pattern, replacement), memo|
          normalized_pattern = pattern.is_a?(Regexp) ? pattern : Regexp.new(Regexp.escape(pattern.to_s))
          memo[normalized_pattern] = normalize_replacement(replacement)
        end
      end

      def default_collation_fallbacks
        {
          /utf8mb3_uca\d+_ai_ci/ => { collation: 'utf8mb4_unicode_ci', charset: 'utf8mb4' },
          /utf8mb3_uca\d+_as_cs/ => { collation: 'utf8mb4_unicode_ci', charset: 'utf8mb4' },
          /utf8mb3_unicode_520_ci/ => { collation: 'utf8mb4_unicode_ci', charset: 'utf8mb4' }
        }
      end

      def charset_fallbacks
        raw_mappings = options.dig(:global, :charset_fallbacks) || default_charset_fallbacks
        return {} unless raw_mappings

        raw_mappings.each_with_object({}) do |(pattern, replacement), memo|
          normalized_pattern = pattern.is_a?(Regexp) ? pattern : Regexp.new(Regexp.escape(pattern.to_s))
          memo[normalized_pattern] = replacement
        end
      end

      def default_charset_fallbacks
        {
          /utf8mb3\b/ => 'utf8mb4'
        }
      end

      def normalize_replacement(replacement)
        return replacement if replacement.is_a?(Hash)

        { collation: replacement, charset: nil }
      end
    end
  end
end
