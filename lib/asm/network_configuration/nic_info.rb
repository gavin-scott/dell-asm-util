require "asm/network_configuration/nic_port"

module ASM
  class NetworkConfiguration
    # NicInfo encapsulates information about a server NIC such as number of ports,
    # link speed of those ports, and the number of NPAR partitions available on
    # each port.
    class NicInfo
      include Comparable

      # Retrieves an array of NicInfo elements for the specified server endpoint.
      #
      # @param endpoint [Hash] the iDrac server endpoint. Should contain at least :host, :user and :password keys
      # @param logger [Logger] logger to use for log messages
      # @return [Array<NicInfo>] the NICs on the specified server
      # @raise [StandardError] when an error occurs retrieving the NIC information
      def self.fetch(endpoint, logger = nil)
        nic_views = ASM::WsMan.get_nic_view(endpoint, logger)
        bios_info = ASM::WsMan.get_bios_enumeration(endpoint, logger)
        NicInfo.create(nic_views, bios_info, logger)
      end

      # Retrieves an array of NicInfo elements for the specified nic_view and bios_information
      #
      # @param nic_views [Array<Hash>] the result of calling {ASM::WsMan.get_nic_view}
      # @param bios_info [Array<Hash>] the result of calling {ASM::WsMan.get_bios_enumeration}
      # @param logger [Logger] logger to use for log messages
      # @return [Array<NicInfo>] the NIC info
      # @raise [StandardError] when the nic_views are inconsistent
      # @api private
      def self.create(nic_views, bios_info, logger = nil)
        prefix_to_views = {}
        nic_views.each do |nic_view|
          i = NicView.new(nic_view)
          prefix_to_views[i.card_prefix] ||= []
          prefix_to_views[i.card_prefix] << i
        end

        prefix_to_views.values.map do |nic_view|
          NicInfo.new(nic_view.sort, bios_info, logger)
        end.sort
      end

      attr_accessor :card_prefix, :vendor, :model, :ports, :nic_info, :nic_views, :nic_status

      # Creates a NicInfo
      #
      # @param nic_views [Array<NicView>] the NicViews associated with the NIC
      # @param bios_info [Array<Hash>] the BIOS enumeration for the server. Used
      #                                to determine if the NIC is disabled.
      # @param logger [Logger] logger to use for log messages
      # @return [NicInfo] the NicInfo
      # @raise [StandardError] when the nic_views are inconsistent
      # @api private
      def initialize(nic_views, bios_info, logger = nil)
        @nic_views = nic_views.sort

        port1 = nic_views.first
        @nic_info ||= port1
        @card_prefix ||= port1.card_prefix
        @vendor ||= port1.nic_view["VendorName"] # WARNING: sometimes this is missing! use PCIVendorID?
        @model ||= port1.nic_view["ProductName"]

        validate_nic_views

        port_nic_views = nic_views.find_all { |i| i.partition_no == "1"}
        @ports = port_nic_views.map do |nic_info|
          NicPort.new(nic_info, port_nic_views.size, logger)
        end

        @nic_status = ASM::WsMan.nic_status(port1.fqdd, bios_info)
      end

      # Validates that the NIC NicView information is consistent
      #
      # Checks that all passed NicView information pertains to the same physical
      # card and that there are no gaps, i.e. information is contained for all
      # ports of the NIC and all partitions of those ports (if applicable).
      #
      # @raise [StandardError] if inconsistent NicView information was provided
      # @api private
      def validate_nic_views
        port = nil
        partition = nil
        nic_views.each do |nic_info|
          unless nic_info.card_prefix == card_prefix
            raise("Card prefix should be %s but was %s" % [card_prefix, nic_info.card_prefix])
          end
          next_port = Integer(nic_info.port)
          next_partition = Integer(nic_info.partition_no)
          if port.nil? && partition.nil?
            port = next_port
            partition = next_partition
          else
            port_diff = next_port - port
            if port_diff == 0 && next_partition != partition + 1
                raise("Partition should be %d got %d" % [partition + 1, next_partition])
            elsif port_diff == 1 && next_partition != 1
                raise("First partition of port %d should be 1 but got %d" % [next_port, next_partition])
            elsif !port_diff.between?(0, 1)
              raise("Skipped from port %d to %d" % [port, next_port])
            end
            port = next_port
            partition = next_partition
          end
        end
      end

      # If the NIC is disabled
      #
      # @return [Boolean]
      def disabled?
        !!(nic_status =~ /disabled/i)
      end

      # If all ports have the same link speed
      #
      # @param ports [Array<NicPort>] the ports
      # @param link_speed [String] the link speed
      # @return [Boolean] if all ports have the same link speed
      def all_ports?(ports, link_speed)
        ports.map { |p| p.link_speed }.uniq == [ link_speed ]
      end

      # A string description of the NIC ports
      #
      # Example return values are 4x10Gb, 2x10Gb, 2x10Gb,2x1Gb, 2x1Gb or unknown.
      #
      # @return [String] the nic type description
      def nic_type
        return "2x10Gb" if ports.size == 2 && all_ports?(ports, "10 Gbps")
        return "2x1Gb" if ports.size == 2 && all_ports?(ports, "1000 Mbps")
        return "4x10Gb" if ports.size == 4 && all_ports?(ports, "10 Gbps")
        return "4x1Gb" if ports.size == 4 && all_ports?(ports, "1000 Mbps")
        return "2x10Gb,2x1Gb" if ports.size == 4 && all_ports?(ports.slice(0, 2), "10 Gbps") && all_ports?(ports.slice(2, 4), "1 Gbps")
        "unknown"
      end

      # The number of NPAR partitions for each 10Gb port on the NIC
      #
      # NICs that do not support NPAR will return 1
      #
      # @raise [StandardError] if different 10Gb ports report different partitioning capabilities
      def n_partitions
        ports_10gb = ports.find_all { |port| port.link_speed == "10 Gbps" }
        ns = ports_10gb.map { |port| port.n_partitions }.uniq
        return 0 if ns.empty?
        return ns.first if ns.size == 1
        raise("Different 10Gb NIC ports on %s reported different number of partitions: %s" %
                  [card_prefix, ports_10gb.map { |p| "NIC: %s # partitions: %s" % [p.model, p.n_partitions] }.join(", ")])
      end

      # Returns the {NicView} for a specified port and partition
      #
      # @param port [String] the port number
      # @param partition [String] the partition number
      # @return [NicView|Void] the NicView if one can be found; nil otherwise
      def find_partition(port, partition)
        nic_views.find do |nic_view|
          nic_view.port == port && nic_view.partition_no == partition
        end
      end

      def to_s
        "#<ASM::NetworkConfiguration::NicCapabilities %s type: %s model: %s>" % [card_prefix, nic_type, model]
      end

      def <=>(other)
        self.nic_info <=> other.nic_info
      end
    end
  end
end
