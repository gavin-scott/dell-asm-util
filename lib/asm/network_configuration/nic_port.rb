module ASM
  class NetworkConfiguration
    class NicPort

      LINK_SPEEDS = [ "Unknown", "10 Mbps", "100 Mbps", "1000 Mbps", "2.5 Gbps", "10 Gbps", "20 Gbps", "40 Gbps", "100 Gbps" ]

      attr_reader :link_speed, :n_ports, :nic_info

      def initialize(nic_info, n_ports, logger = nil)
        @nic_info = nic_info
        @n_ports = n_ports
        nic_view = nic_info.nic_view
        @vendor ||= nic_view["VendorName"] # WARNING: sometimes this is missing! use PCIVendorID?
        @model ||= nic_view["ProductName"]
        @link_speed = nic_view["LinkSpeed"] ? LINK_SPEEDS[Integer(nic_view["LinkSpeed"])] : nil
        @link_speed ||= model_speed
        @link_speed ||= LINK_SPEEDS[0]
      end

      def vendor
        nic_view = nic_info.nic_view
        return :qlogic if nic_view["VendorName"] =~ /qlogic|broadcom/i
        return :qlogic if nic_view["PCIVendorID"] == "14e4"
        return :intel if nic_view["VendorName"] =~ /intel/i
        :intel if nic_view["PCIVendorID"] == "8086" # have seen cases where VendorName not populated
      end

      def product
        nic_info.nic_view["ProductName"]
      end

      def port
        Integer(nic_info.port)
      end

      def is_qlogic_57800?
        vendor == :qlogic && product =~ /57800/ && n_ports == 4
      end

      def is_qlogic_57810?
        vendor == :qlogic && product =~ /57810/ && n_ports == 2
      end

      def is_qlogic_57840?
        vendor == :qlogic && product =~ /57840/ && n_ports == 4
      end

      def is_intel_x520?
        # NOTE: there appear to be other X520 variants that are e.g. 2x10Gb,2x1Gb
        # but limiting support here to 2x10Gb
        vendor == :intel && product =~ /x520/i && n_ports == 2
      end

      def model_speed
        return "10 Gbps" if is_qlogic_57810?
        return "10 Gbps" if is_qlogic_57840?

        # Broadcom / QLogic 57800 is a 2x10Gb, 2x1Gb NIC
        return "10 Gbps" if is_qlogic_57800? && port.between?(1, 2)
        return "1 Gbps" if is_qlogic_57800? && port.between?(3, 4)

        return "10 Gbps" if is_intel_x520?
        nil
      end

      def n_partitions
        return 4 if is_qlogic_57810?
        return 2 if is_qlogic_57840?
        return 2 if is_qlogic_57800? && port.between?(1, 2)
        1
      end

    end
  end
end
