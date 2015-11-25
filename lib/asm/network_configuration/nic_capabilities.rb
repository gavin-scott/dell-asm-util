require "asm/network_configuration/nic_port"

module ASM
  class NetworkConfiguration
    class NicCapabilities
      include Comparable

      def self.fetch(endpoint, logger = nil)
        nic_views = ASM::WsMan.get_nic_view(endpoint, logger)
        bios_info = ASM::WsMan.get_bios_enumeration(endpoint, logger)
        NicCapabilities.create(nic_views, bios_info, logger)
      end

      def self.create(nic_views, bios_info, logger = nil)
        prefix_to_views = {}
        nic_views.each do |nic_view|
          i = NicInfo.new(nic_view)
          prefix_to_views[i.card_prefix] ||= []
          prefix_to_views[i.card_prefix] << i
        end

        prefix_to_views.values.map do |nic_infos|
          NicCapabilities.new(nic_infos.sort, bios_info, logger)
        end.sort
      end

      attr_accessor :card_prefix, :vendor, :model, :ports, :nic_info, :nic_infos, :nic_status

      def initialize(nic_infos, bios_info, logger = nil)
        @nic_infos = nic_infos.sort

        port1 = nic_infos.first
        @nic_info ||= port1
        @card_prefix ||= port1.card_prefix
        @vendor ||= port1.nic_view["VendorName"] # WARNING: sometimes this is missing! use PCIVendorID?
        @model ||= port1.nic_view["ProductName"]

        validate_sequential_nic_infos

        port_nic_infos = nic_infos.find_all { |i| i.partition_no == "1"}
        @ports = port_nic_infos.map do |nic_info|
          NicPort.new(nic_info, port_nic_infos.size, logger)
        end

        @nic_status = ASM::WsMan.nic_status(port1.fqdd, bios_info)
      end

      def validate_sequential_nic_infos
        port = nil
        partition = nil
        nic_infos.each do |nic_info|
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

      def disabled?
        !!(nic_status =~ /disabled/i)
      end

      def all_ports?(ports, link_speed)
        ports.map { |p| p.link_speed }.uniq == [ link_speed ]
      end

      def nic_type
        return "2x10Gb" if ports.size == 2 && all_ports?(ports, "10 Gbps")
        return "2x1Gb" if ports.size == 2 && all_ports?(ports, "1000 Mbps")
        return "4x10Gb" if ports.size == 4 && all_ports?(ports, "10 Gbps")
        return "4x1Gb" if ports.size == 4 && all_ports?(ports, "1000 Mbps")
        return "2x10Gb,2x1Gb" if ports.size == 4 && all_ports?(ports.slice(0, 2), "10 Gbps") && all_ports?(ports.slice(2, 4), "1 Gbps")
        "unknown"
      end

      def n_partitions
        ports_10gb = ports.find_all { |port| port.link_speed == "10 Gbps" }
        ns = ports_10gb.map { |port| port.n_partitions }.uniq
        return 0 if ns.empty?
        return ns.first if ns.size == 1
        raise("Different 10Gb NIC ports on %s reported different number of partitions: %s" %
                  [card_prefix, ports_10gb.map { |p| "NIC: %s # partitions: %s" % [p.model, p.n_partitions] }.join(", ")])
      end

      def find_partition(port, partition)
        nic_infos.find do |nic_info|
          nic_info.port == port && nic_info.partition_no == partition
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
