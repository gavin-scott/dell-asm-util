module ASM
  class Error < StandardError; end
  class CommandException < Error; end
  class SyncException < Error; end
  class PuppetEventException < Error; end
  class NotFoundException < Error; end
  class GraphiteException < Error; end
  class NagiosException < Error; end

  # A UserException message can be displayed directly to the user
  class UserException < Error; end

  class RetryException < StandardError; end

  # An exception that encapsulates a ws-man response.
  class ResponseError < StandardError
    attr_reader :response

    def initialize(msg, response)
      super(msg)
      @response = response
    end

    def to_s
      "%s: %s" % [super.to_s, ASM::WsMan::Parser.response_string(response)]
    end
  end
end
