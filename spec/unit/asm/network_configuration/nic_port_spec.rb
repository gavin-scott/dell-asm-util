require 'spec_helper'
require 'asm/network_configuration/nic_info'
require 'asm/network_configuration/nic_port'

describe ASM::NetworkConfiguration::NicPort do
  let(:logger) { stub(:debug => nil, :warn => nil, :info => nil, :error => nil) }

  describe "NicPort.new" do
    let (:endpoint) { mock("rspec-endpoint") }

    it "should use LinkSpeed for 10Gbps NIC" do
      nic_view = {"FQDD" => "NIC.Integrated.1-1-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "LinkSpeed" => "5"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 1, logger)
      expect(port.link_speed).to eq("10 Gbps")
    end

    it "should use LinkSpeed for 1Gbps NIC" do
      nic_view = {"FQDD" => "NIC.Integrated.1-1-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "LinkSpeed" => "3"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 1, logger)
      expect(port.link_speed).to eq("1000 Mbps")
    end

    it "should override Broadcom 57800 LinkSpeed for port 1 to 10 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-1-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Broadcom",
                  "ProductName" => "57800"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 4, logger)
      expect(port.link_speed).to eq("10 Gbps")
    end

    it "should override Broadcom 57800 LinkSpeed for port 3 to 1 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-3-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Broadcom",
                  "ProductName" => "57800"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 4, logger)
      expect(port.link_speed).to eq("1 Gbps")
    end

    it "should override Broadcom 57810 LinkSpeed for port 1 of 2-port NIC to 10 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-1-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Broadcom",
                  "ProductName" => "57810"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 2, logger)
      expect(port.link_speed).to eq("10 Gbps")
    end

    it "should not override Broadcom 57810 LinkSpeed for port 1 of 4-port NIC to 10 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-1-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Broadcom",
                  "ProductName" => "57810"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 4, logger)
      expect(port.link_speed).to eq("Unknown")
    end

    it "should override Broadcom 57840 LinkSpeed for port 3 of 4-port NIC to 10 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-3-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Broadcom",
                  "ProductName" => "57840"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 4, logger)
      expect(port.link_speed).to eq("10 Gbps")
    end

    it "should not override Broadcom 57840 LinkSpeed for port 3 of 2-port NIC to 10 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-3-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Broadcom",
                  "ProductName" => "57840"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 2, logger)
      expect(port.link_speed).to eq("Unknown")
    end

    it "should override Intel X520 LinkSpeed for port 2 of 2-port NIC to 10 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-2-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Intel",
                  "ProductName" => "X520"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 2, logger)
      expect(port.link_speed).to eq("10 Gbps")
    end

    it "should override Intel X520 LinkSpeed for port 2 of 2-port NIC to 10 Gbps when only PCIVendorID available" do
      nic_view = {"FQDD" => "NIC.Integrated.1-2-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "PCIVendorID" => "8086",
                  "ProductName" => "X520"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 2, logger)
      expect(port.link_speed).to eq("10 Gbps")
    end

    it "should not override Intel X520 LinkSpeed for port 1 of 4-port NIC to 10 Gbps" do
      nic_view = {"FQDD" => "NIC.Integrated.1-1-1",
                  "CurrentMACAddress" => "04:0A:F7:06:88:50",
                  "PermanentMACAddress" => "04:0A:F7:06:88:50",
                  "VendorName" => "Intel",
                  "ProductName" => "X520"}
      nic_info = ASM::NetworkConfiguration::NicInfo.new(nic_view)
      port = ASM::NetworkConfiguration::NicPort.new(nic_info, 4, logger)
      expect(port.link_speed).to eq("Unknown")
    end
  end

  describe "#n_partitions" do
    let (:nic_info) { ASM::NetworkConfiguration::NicInfo.new({"FQDD" => "NIC.Integrated.1-1-1"}) }
    let (:nic_port) { ASM::NetworkConfiguration::NicPort.new(nic_info, 2, logger) }

    it "should return 2 for QLogic 57800" do
      nic_port.expects(:is_qlogic_57800?).returns(true)
      expect(nic_port.n_partitions).to eq(2)
    end

    it "should return 4 for QLogic 57810" do
      nic_port.expects(:is_qlogic_57810?).returns(true)
      expect(nic_port.n_partitions).to eq(4)
    end

    it "should return 2 for QLogic 57840" do
      nic_port.expects(:is_qlogic_57840?).returns(true)
      expect(nic_port.n_partitions).to eq(2)
    end

    it "should return 1 otherwise" do
      expect(nic_port.n_partitions).to eq(1)
    end
  end
end
