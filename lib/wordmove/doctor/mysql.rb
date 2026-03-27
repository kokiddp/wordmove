module Wordmove
  class Doctor
    class Mysql
      attr_reader :config, :logger

      def initialize(movefile_name = nil, movefile_dir = '.')
        @logger = Logger.new(STDOUT).tap { |l| l.level = Logger::INFO }
        begin
          @config = Wordmove::Movefile.new(movefile_name, movefile_dir).fetch[:local][:database]
        rescue Psych::SyntaxError
          return
        end
      end

      def check!
        logger.task "Checking local database commands and connection"

        return logger.error "Can't connect to mysql using your movefile.yml" if config.nil?

        mysql_client_doctor
        mysqldump_doctor
        mysql_server_doctor
        mysql_database_doctor
      end

      private

      def mysql_client_doctor
        if mysql_client_in_path?
          logger.success "`mysql`/`mariadb` command is in $PATH"
        else
          logger.error "`mysql`/`mariadb` command is not in $PATH"
        end
      end

      def mysqldump_doctor
        if mysqldump_in_path?
          logger.success "`mysqldump`/`mariadb-dump` command is in $PATH"
        else
          logger.error "`mysqldump`/`mariadb-dump` command is not in $PATH"
        end
      end

      def mysql_server_doctor
        command = mysql_command

        if system(command, out: File::NULL, err: File::NULL)
          logger.success "Successfully connected to the MySQL server"
        else
          logger.error <<-LONG
  We can't connect to the MySQL server using credentials
                specified in the Movefile. Double check them or try
                to debug your system configuration.

                The command used to test was:

                #{command}
          LONG
        end
      end

      def mysql_database_doctor
        command = mysql_command(database: config[:name])

        if system(command, out: File::NULL, err: File::NULL)
          logger.success "Successfully connected to the database"
        else
          logger.error <<-LONG
  We can't connect to the database using credentials
                specified in the Movefile, or the database does not
                exists. Double check them or try to debug your
                system configuration.

                The command used to test was:

                #{command}
          LONG
        end
      end

      def mysql_command(database: nil)
        mysql_options = config[:mysql_options]
        command = [mysql_client_binary]
        command << "--host=#{Shellwords.escape(config[:host])}" if config[:host].present?
        command << "--port=#{Shellwords.escape(config[:port])}" if config[:port].present?
        if (socket = mysql_socket_option)
          command << "--socket=#{Shellwords.escape(socket)}"
        end
        command << "--user=#{Shellwords.escape(config[:user])}" if config[:user].present?
        if config[:password].present?
          command << "--password=#{Shellwords.escape(config[:password])}"
        end
        command << Shellwords.split(mysql_options) if mysql_options.present?
        command << database if database.present?
        command << "-e'QUIT'"
        command.join(" ")
      end

      def mysql_client_binary
        '$(command -v mariadb >/dev/null 2>&1 && echo mariadb || echo mysql)'
      end

      def mysql_client_in_path?
        system("which mysql", out: File::NULL) || system("which mariadb", out: File::NULL)
      end

      def mysqldump_in_path?
        system("which mysqldump", out: File::NULL) || system("which mariadb-dump", out: File::NULL)
      end

      def mysql_socket_option
        return if mysql_option_includes_socket?(config[:mysql_options])

        config[:socket].presence || mysql_socket_from_options(config[:mysqldump_options])
      end

      def mysql_option_includes_socket?(option_string)
        mysql_socket_from_options(option_string).present?
      end

      def mysql_socket_from_options(option_string)
        return if option_string.to_s.empty?

        args = Shellwords.split(option_string)
        socket_index = args.index('--socket')
        return args[socket_index + 1] if socket_index && args[socket_index + 1]

        args.each do |arg|
          return Regexp.last_match(1) if arg.match(/\A--socket=(.+)\z/)
        end

        nil
      end
    end
  end
end
