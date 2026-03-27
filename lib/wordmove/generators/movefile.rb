module Wordmove
  module Generators
    class Movefile < Thor::Group
      include Thor::Actions
      include MovefileAdapter

      def self.source_root
        File.dirname(__FILE__)
      end

      def copy_movefile
        template "movefile.yml"
        uncomment_local_database_connection_overrides
      end

      no_commands do
        def uncomment_local_database_connection_overrides
          content = File.read(movefile_path)
          updated = uncomment_local_port(content)
          updated = uncomment_local_socket(updated)
          File.write(movefile_path, updated)
        end

        def movefile_path
          File.join(destination_root, "movefile.yml")
        end

        def uncomment_local_port(content)
          port = database.respond_to?(:port) ? database.port : nil
          return content if port.to_s.empty?

          content.sub(
            /^(\s*)# port: 3306$/,
            "\\1port: #{port}"
          )
        end

        def uncomment_local_socket(content)
          socket = database.respond_to?(:socket) ? database.socket : nil
          return content if socket.to_s.empty?

          content.sub(
            /^(\s*)# socket: \/path\/to\/mysql\.sock # optional unix socket path$/,
            "\\1socket: #{socket.inspect} # optional unix socket path"
          )
        end
      end
    end
  end
end
