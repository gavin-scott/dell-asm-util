require "asm/network_configuration/nic_port"

module ASM
  class NetworkConfiguration
    class NicCapabilities
      include Comparable

      attr_accessor :card_prefix, :vendor, :model, :ports, :nic_info, :nic_infos

      def self.create(nic_views, logger = nil)
        prefix_to_views = {}
        nic_views.each do |nic_view|
          i = NicInfo.new(nic_view)
          prefix_to_views[i.card_prefix] ||= []
          prefix_to_views[i.card_prefix] << i
        end

        prefix_to_views.values.map do |nic_infos|
          NicCapabilities.new(nic_infos.sort, logger)
        end.sort
      end

      def initialize(nic_infos, logger = nil)
        @nic_infos = nic_infos.sort
        # TODO: ensure there are not gaps. E.g. port 1 and port 3 but no port 2 or partition 2 and partition 4 but no partition 3
        # TODO: skip disabled NICS

        port1 = nic_infos.first
        @nic_info ||= port1
        @card_prefix ||= port1.card_prefix
        @vendor ||= port1.nic_view["VendorName"] # WARNING: sometimes this is missing! use PCIVendorID?
        @model ||= port1.nic_view["ProductName"]

        # TODO: validate that we have a NicView for every port
        port_nic_infos = nic_infos.find_all { |i| i.partition_no == "1"}
        @ports = port_nic_infos.map do |nic_info|
          NicPort.new(nic_info, port_nic_infos.size, logger)
        end
      end

      def all_ports?(ports, link_speed)
        ports.map { |p| p.link_speed }.uniq == [ link_speed ]
      end

      def nic_type
        return "2x10Gb" if ports.size == 2 && all_ports?(ports, "10 Gbps")
        return "2x1Gb" if ports.size == 2 && all_ports?(ports, "1 Gbps")
        return "4x10Gb" if ports.size == 4 && all_ports?(ports, "10 Gbps")
        return "4x1Gb" if ports.size == 4 && all_ports?(ports, "1 Gbps")
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
