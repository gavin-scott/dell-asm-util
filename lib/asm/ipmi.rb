require "asm/ipmi/client"

module ASM
  class Ipmi
    class Error < StandardError; end

    attr_reader :client

    def initialize(endpoint, options={})
      @client = Client.new(endpoint, options)
    end

    def logger
      client.logger
    end

    def host
      client.host
    end

    def reboot
      if get_power_status == "off"
        logger.info("Server is powered-off. Need to power-on the server")
        client.exec("power on")
      else
        client.exec("power cycle")
      end
    end

    # @deprecated Use {#reboot} instead
    def self.reboot(endpoint, logger=nil)
      ASM::Ipmi.new(endpoint, :logger => logger).reboot
    end

    def get_power_status # rubocop:disable Style/AccessorMethodName
      power_status = client.exec("power status")
      power_status = power_status.scan(/Chassis Power is\s+(\S+)$/m).flatten.first.strip
      logger.debug("Current power status: #{power_status}") if logger
      power_status
    end

    # @deprecated Use {#get_power_status} instead
    def self.get_power_status(endpoint, logger=nil)
      ASM::Ipmi.new(endpoint, :logger => logger).get_power_status
    end

    def power_on
      if get_power_status == "on"
        logger.info("Server is already powered-on.")
        return
      end
      client.exec("power on")
    end

    # @deprecated Use {#power_on} instead
    def self.power_on(endpoint, logger=nil)
      ASM::Ipmi.new(endpoint, :logger => logger).power_on
    end

    def power_off
      if get_power_status == "off"
        logger.info("Server is already powered-off.")
        return true
      end
      client.exec("power off")
    end

    # @deprecated Use {#power_off} instead
    def self.power_off(endpoint, logger=nil)
      ASM::Ipmi.new(endpoint, :logger => logger).power_off
    end
  end
end
