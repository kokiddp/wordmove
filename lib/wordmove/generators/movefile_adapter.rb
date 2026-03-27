require 'shellwords'

module Wordmove
  module Generators
    module MovefileAdapter
      def vhost
        VhostReader.config
      end

      def wordpress_path
        File.expand_path(Dir.pwd)
      end

      def database
        DBConfigReader.config
      end
    end

    class DBConfigReader
      def self.config
        new.config
      end

      def config
        OpenStruct.new(database_config)
      end

      def database_config
        if wp_config_exists?
          WordpressDBConfig.config
        else
          DefaultDBConfig.config
        end
      end

      def wp_config_exists?
        File.exist?(WordpressDirectory.default_path_for(:wp_config))
      end
    end

    class DefaultDBConfig
      def self.config
        {
          name: "database_name",
          user: "user",
          password: "password",
          host: "127.0.0.1"
        }
      end
    end

    class VhostReader
      def self.config
        new.config
      end

      def config
        wp_config_vhost || wp_cli_vhost || default_vhost
      end

      def default_vhost
        "http://vhost.local"
      end

      def wordpress_path
        File.expand_path(Dir.pwd)
      end

      def wp_config_exists?
        File.exist?(WordpressDirectory.default_path_for(:wp_config))
      end

      def wp_config
        @wp_config ||= File.read(
          WordpressDirectory.default_path_for(:wp_config)
        ).encode('utf-8', invalid: :replace)
      end

      def wp_config_vhost
        return unless wp_config_exists?

        %w[WP_HOME WP_SITEURL].each do |definition|
          wp_config.match(wp_definition_regex(definition)) do |match|
            value = match[:value].to_s.strip
            return value unless value.empty?
          end
        end

        nil
      end

      def wp_cli_vhost
        return unless wp_config_exists?
        return unless wp_in_path?

        read_wp_option('home').presence || read_wp_option('siteurl').presence
      end

      def wp_in_path?
        system('which wp > /dev/null 2>&1')
      end

      def read_wp_option(option)
        command = [
          "wp option get #{option}",
          "--path=#{Shellwords.escape(wordpress_path)}",
          "--allow-root",
          "2>/dev/null"
        ].join(' ')

        `#{command}`.strip
      end

      def wp_definition_regex(definition)
        /
          ^\s*define\(
          \s*['"]#{Regexp.escape(definition)}['"]
          \s*,\s*
          (?<quote>['"])
          (?<value>(?:\\.|(?!\k<quote>).)*)
          \k<quote>
          \s*\)\s*;?
        /x
      end
    end

    class WordpressDBConfig
      def self.config
        new.config
      end

      def wp_config
        @wp_config ||= File.read(
          WordpressDirectory.default_path_for(:wp_config)
        ).encode('utf-8', invalid: :replace)
      end

      def wp_definitions
        {
          name: 'DB_NAME',
          user: 'DB_USER',
          password: 'DB_PASSWORD',
          host: 'DB_HOST'
        }
      end

      def wp_definition_regex(definition)
        /
          ^\s*define\(
          \s*['"]#{Regexp.escape(definition)}['"]
          \s*,\s*
          (?<quote>['"])
          (?<value>(?:\\.|(?!\k<quote>).)*)
          \k<quote>
          \s*\)\s*;?
        /x
      end

      def defaults
        DefaultDBConfig.config.clone
      end

      def config
        config = wp_definitions.each_with_object(defaults) do |(key, definition), result|
          wp_config.match(wp_definition_regex(definition)) do |match|
            result[key] = match[:value]
          end
        end

        normalize_host_config(config)
      end

      def normalize_host_config(config)
        host = config[:host].to_s

        if host.match(/\A(?<hostname>[^:]+):(?<socket>\/.+)\z/)
          config[:host] = Regexp.last_match[:hostname]
          config[:socket] = Regexp.last_match[:socket]
        elsif host.match(/\A(?<hostname>[^:]+):(?<port>\d+)\z/)
          config[:host] = Regexp.last_match[:hostname]
          config[:port] = Regexp.last_match[:port]
        end

        config
      end
    end
  end
end
