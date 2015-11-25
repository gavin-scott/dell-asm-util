module ASM
  class NetworkConfiguration
    class NicPort

      # [Description ("Link Speed."),
      #              ValueMap { "0", "1", "2", "3", "4", "5", "6", "7", "8"},
      #              Values { "Unknown", "10 Mbps", "100 Mbps", "1000 Mbps",
      #                  "2.5 Gbps", "10 Gbps", "20 Gbps", "40 Gbps", "100 Gbps" }]
      # uint8 LinkSpeed;
      LINK_SPEEDS = [ "Unknown", "10 Mbps", "100 Mbps", "1000 Mbps", "2.5 Gbps", "10 Gbps", "20 Gbps", "40 Gbps", "100 Gbps" ]

      attr_reader :link_speed, :n_ports

      def initialize(nic_info, n_ports, logger = nil)
        @n_ports = n_ports
        nic_view = nic_info.nic_view
        @vendor ||= nic_view["VendorName"] # WARNING: sometimes this is missing! use PCIVendorID?
        @model ||= nic_view["ProductName"]
        @link_speed = nic_view["LinkSpeed"] ? LINK_SPEEDS[Integer(nic_view["LinkSpeed"])] : nil
        @link_speed ||= model_speed(nic_info)
        @link_speed ||= "unknown"
      end

      def nic_vendor(nic_view)
        return :qlogic if nic_view["VendorName"] =~ /qlogic|broadcom/i
        return :qlogic if nic_view["PCIVendorID"] == "14e4"
        return :intel if nic_view["VendorName"] =~ /intel/i
        :intel if nic_view["PCIVendorID"] == "8086" # have seen cases where VendorName not populated
      end

      def model_speed(nic_info)
        nic_view = nic_info.nic_view
        case nic_vendor(nic_view)
          when :qlogic
            qlogic_speed(nic_view["ProductName"], nic_info.port)
          when :intel
            intel_speed(nic_view["ProductName"], nic_info.port)
          else
            nil
        end
      end

      def qlogic_speed(product, port)
        return "10 Gbps" if product =~ /57840/ && n_ports == 4
        return "10 Gbps" if product =~ /57810/ && n_ports == 2
        return "10 Gbps" if product =~ /57800/ && n_ports == 4 && %w(1 2).include?(port)
        "1 Gbps" if product =~ /57800/ && n_ports == 4 && %w(3 4).include?(port)
      end

      def intel_speed(product, port)
        "10 Gbps" if product =~ /X520/ && n_ports == 2
      end
    end
  end
end
