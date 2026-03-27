require 'shellwords'

module Wordmove
  class Logger < ::Logger
    MAX_LINE = 70

    def initialize(device, strings_to_hide = [])
      super(device, formatter: proc { |_severity, _datetime, _progname, message|
        formatted_message = if strings_to_hide.empty?
                              message
                            else
                              message.gsub(
                                Regexp.new(
                                  strings_to_hide.map { |string| Regexp.escape(string) }.join('|')
                                ),
                                '[secret]'
                              )
                            end

        "\n#{formatted_message}\n"
      })
    end

    def task(title)
      prefix = "▬" * 2
      title = " #{title} "
      padding = "▬" * padding_length(title)
      add(INFO, prefix + title.light_white + padding)
    end

    def task_step(local_step, title)
      if local_step
        add(INFO, "    local".cyan + " | ".black + format_task_step(title))
      else
        add(INFO, "   remote".yellow + " | ".black + format_task_step(title))
      end
    end

    def error(message)
      add(ERROR, "    ❌  error".red + " | ".black + message.to_s)
    end

    def success(message)
      add(INFO, "    ✅  success".green + " | ".black + message.to_s)
    end

    def debug(message)
      add(DEBUG, "    🛠  debug".magenta + " | ".black + message.to_s)
    end

    def warn(message)
      add(WARN, "    ⚠️  warning".yellow + " | ".black + message.to_s)
    end

    def info(message)
      add(INFO, "    ℹ️  info".yellow + " | ".black + message.to_s)
    end

    def plain(message)
      add(INFO, message.to_s)
    end

    private

    def padding_length(line)
      result = MAX_LINE - line.length
      result.positive? ? result : 0
    end

    def format_task_step(title)
      message = title.to_s
      return message if passthrough_task_step?(message)

      lines = message.lines(chomp: true).reject(&:empty?)
      return summarized_single_line_command(message) if lines.size <= 1
      return mysql_import_summary(message) if mysql_import_script?(message)

      "run shell script"
    end

    def passthrough_task_step?(message)
      prefixes = [
        "Exec command:",
        "Output:",
        "download ",
        "delete:",
        "get:",
        "put:",
        "get_directory:",
        "put_directory:"
      ]

      return true if prefixes.any? { |prefix| message.start_with?(prefix) }
      return false if message.include?("\n")

      summarized_single_line_command(message) == message
    end

    def mysql_import_script?(message)
      message.include?('tmp_dump="$(mktemp)"') &&
        message.include?('COMMIT;') &&
        message.include?('--init-command=')
    end

    def mysql_import_summary(message)
      dump_path = message[%r{head -n 1 (.+?) 2>/dev/null \|\| true}, 1]
      database = message[/--database=([^\s]+)/, 1]

      summary = +"import SQL dump"
      summary << " #{dump_path}" if dump_path
      summary << " into database #{database}" if database
      summary << " (strip sandbox header, append COMMIT)"
      summary
    end

    def summarized_single_line_command(message)
      mysql_dump_summary(message) ||
        gzip_summary(message) ||
        wp_search_replace_summary(message) ||
        message
    end

    def mysql_dump_summary(message)
      return unless message.include?('--result-file=')
      return unless message.include?('mariadb-dump') || message.include?('mysqldump')

      dump_path = message[/--result-file="([^"]+)"/, 1]
      database = message[/\s([^\s]+)\z/, 1]
      return unless dump_path && database

      "dump database #{database} to #{dump_path}"
    end

    def gzip_summary(message)
      if (path = message[/\Agzip -9 -f "([^"]+)"\z/, 1])
        return "compress #{path}"
      end

      if (path = message[/\Agzip -d -f "([^"]+)"\z/, 1])
        return "decompress #{path}"
      end

      nil
    end

    def wp_search_replace_summary(message)
      return unless message.start_with?('wp search-replace ')

      args = Shellwords.split(message)
      return if args.length < 4

      path = args.find { |arg| arg.start_with?('--path=') }&.split('=', 2)&.last
      positional = args.drop(2).reject { |arg| arg.start_with?('--') }
      return if positional.length < 2

      search = positional[0]
      replace = positional[1]

      summary = +"wp search-replace #{search} -> #{replace}"
      summary << " in #{path}" if path
      summary
    end
  end
end
