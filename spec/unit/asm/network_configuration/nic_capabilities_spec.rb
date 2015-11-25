require 'spec_helper'
require 'asm/network_configuration'
require 'asm/network_configuration/nic_capabilities'

describe ASM::NetworkConfiguration::NicCapabilities do
  before do
    SpecHelper.init_i18n
  end

  describe "NicCapabilities.create" do
    let(:logger) { stub(:debug => nil, :warn => nil, :info => nil, :error => nil) }
    let (:endpoint) { mock("rspec-endpoint") }

    it "should parse C6320 Intel X520 Embedded NIC and X540-AT2 mezzanine NIC" do
      raw_nic_view = SpecHelper.load_fixture("network_configuration/nic_capabilities/c6320_nic_view.txt")
      ASM::WsMan.expects(:invoke).returns(raw_nic_view)
      nic_views = ASM::WsMan.get_nic_view(endpoint, logger)
      nics = ASM::NetworkConfiguration::NicCapabilities.create(nic_views, [], logger)
      expect(nics.size).to eq(2)
      expect(nics[0].nic_type).to eq("2x10Gb")
      expect(nics[1].nic_type).to eq("unknown")
    end

    it "should parse M620 with Integrated QLogic NIC" do
      raw_nic_view = SpecHelper.load_fixture("network_configuration/nic_capabilities/m620_nic_view.txt")
      ASM::WsMan.expects(:invoke).returns(raw_nic_view)
      nic_views = ASM::WsMan.get_nic_view(endpoint, logger)
      nics = ASM::NetworkConfiguration::NicCapabilities.create(nic_views, [], logger)
      expect(nics.size).to eq(1)
      expect(nics[0].nic_type).to eq("2x10Gb")
    end

    it "should override 57800 speed" do
      fqdd_to_mac = {"NIC.Integrated.1-1-1" => "04:0A:F7:06:88:50",
                     "NIC.Integrated.1-2-1" => "04:0A:F7:06:88:52",
                     "NIC.Integrated.1-3-1" => "04:0A:F7:06:88:53",
                     "NIC.Integrated.1-4-1" => "04:0A:F7:06:88:54",
      }
      nic_views = fqdd_to_mac.keys.map do |fqdd|
        mac = fqdd_to_mac[fqdd]
        nic_view = {"FQDD" => fqdd, "PermanentMACAddress" => mac, "CurrentMACAddress" => mac}
        if fqdd =~ /Integrated/
          nic_view["VendorName"] = "Broadcom"
          nic_view["ProductName"] = "57800"
        end
        nic_view
      end
      nics = ASM::NetworkConfiguration::NicCapabilities.create(nic_views, [], logger)
      expect(nics.size).to eq(1)
      expect(nics[0].nic_type).to eq("2x10Gb,2x1Gb")
      expect(nics[0].disabled?).to eq(false)
    end

    it "should set disabled?" do
      fqdd_to_mac = {"NIC.Integrated.1-1-1" => "04:0A:F7:06:88:50",
                     "NIC.Integrated.1-2-1" => "04:0A:F7:06:88:52",
                     "NIC.Integrated.1-3-1" => "04:0A:F7:06:88:53",
                     "NIC.Integrated.1-4-1" => "04:0A:F7:06:88:54",
      }
      nic_views = fqdd_to_mac.keys.map do |fqdd|
        mac = fqdd_to_mac[fqdd]
        nic_view = {"FQDD" => fqdd, "PermanentMACAddress" => mac, "CurrentMACAddress" => mac}
        if fqdd =~ /Integrated/
          nic_view["VendorName"] = "Broadcom"
          nic_view["ProductName"] = "57800"
        end
        nic_view
      end
      bios_info = [{"AttributeDisplayName" => "Integrated Network Card 1", "CurrentValue" => "DisabledOS"}]
      nics = ASM::NetworkConfiguration::NicCapabilities.create(nic_views, bios_info, logger)
      expect(nics.size).to eq(1)
      expect(nics[0].nic_type).to eq("2x10Gb,2x1Gb")
      expect(nics[0].disabled?).to eq(true)
    end
  end
end
