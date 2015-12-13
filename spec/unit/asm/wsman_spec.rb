require 'spec_helper'
require 'asm/wsman'

describe ASM::WsMan do
  let(:logger) { stub(:debug => nil, :warn => nil, :info => nil) }
  let(:endpoint) { mock("rspec-endpoint") }

  describe 'when parsing nicview with disabled 57800 and dual-port slot nic' do
    before do
      # NOTE: this data is from a rack with a dual-port slot nic and a quad-port
      # integrated nic. Note the quad-port nic isn't showing any current or
      # permanent mac addresses, so it isn't found in the get_mac_addresses call
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'wsman', 'nic_view.xml')
      @nic_view_response = File.read(file_name)
    end

    it 'should find current macs' do
      ASM::WsMan.stubs(:invoke).returns(@nic_view_response)
      macs = ASM::WsMan.get_mac_addresses(nil, nil)
      macs.should == {'NIC.Slot.2-1-1' => '00:0A:F7:06:9D:C0',
                      'NIC.Slot.2-1-2' => '00:0A:F7:06:9D:C4',
                      'NIC.Slot.2-1-3' => '00:0A:F7:06:9D:C8',
                      'NIC.Slot.2-1-4' => '00:0A:F7:06:9D:CC',
                      'NIC.Slot.2-2-1' => '00:0A:F7:06:9D:C2',
                      'NIC.Slot.2-2-2' => '00:0A:F7:06:9D:C6',
                      'NIC.Slot.2-2-3' => '00:0A:F7:06:9D:CA',
                      'NIC.Slot.2-2-4' => '00:0A:F7:06:9D:CE',
      }
    end

    it 'should find permanent macs' do
      ASM::WsMan.stubs(:invoke).returns(@nic_view_response)
      macs = ASM::WsMan.get_permanent_mac_addresses(nil, nil)
      macs.should == {'NIC.Slot.2-1-1' => '00:0A:F7:06:9D:C0',
                      'NIC.Slot.2-1-2' => '00:0A:F7:06:9D:C4',
                      'NIC.Slot.2-1-3' => '00:0A:F7:06:9D:C8',
                      'NIC.Slot.2-1-4' => '00:0A:F7:06:9D:CC',
                      'NIC.Slot.2-2-1' => '00:0A:F7:06:9D:C2',
                      'NIC.Slot.2-2-2' => '00:0A:F7:06:9D:C6',
                      'NIC.Slot.2-2-3' => '00:0A:F7:06:9D:CA',
                      'NIC.Slot.2-2-4' => '00:0A:F7:06:9D:CE',
      }
    end

  end

  describe 'when parsing nicview with enabled 5720 and dual-port slot nic' do

    before do
      # NOTE: this data is from a rack with a dual-port slot nic and a quad-port
      # integrated nic.
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'wsman', 'nic_view_57800.xml')
      @nic_view_response = File.read(file_name)
    end

    it 'should ignore Broadcom 5720 NICs' do
      # we don't have NicView output, so just make the 57810 look like a 5720
      @nic_view_response.gsub!(/(ProductName[>]Broadcom.*)BCM57800/, '\1BCM5720')
      ASM::WsMan.stubs(:invoke).returns(@nic_view_response)
      macs = ASM::WsMan.get_mac_addresses(nil, nil)
      macs.should == {'NIC.Slot.2-1-1' => '00:0A:F7:06:9E:20',
                      'NIC.Slot.2-1-2' => '00:0A:F7:06:9E:24',
                      'NIC.Slot.2-1-3' => '00:0A:F7:06:9E:28',
                      'NIC.Slot.2-1-4' => '00:0A:F7:06:9E:2C',
                      'NIC.Slot.2-2-1' => '00:0A:F7:06:9E:22',
                      'NIC.Slot.2-2-2' => '00:0A:F7:06:9E:26',
                      'NIC.Slot.2-2-3' => '00:0A:F7:06:9E:2A',
                      'NIC.Slot.2-2-4' => '00:0A:F7:06:9E:2E'}
    end
  end

  describe "#response_string" do
    it "should display message" do
      resp = {:lcstatus => "5",
              :message => "Lifecycle Controller Remote Services is not ready."}
      expect(ASM::WsMan.response_string(resp)).to eq("Lifecycle Controller Remote Services is not ready. [lcstatus: 5]")
    end
  end

  describe "ResponseError#to_s" do
    it "should display message" do
      e = ASM::WsMan::ResponseError.new("Exception message", {:message => "ws-man message", :message_id => "4"})
      expect(e.to_s).to eq("Exception message: ws-man message [message_id: 4]")
    end

    it "should display fault reason" do
      e = ASM::WsMan::ResponseError.new("Exception message", {:reason => "ws-man fault reason", :message_id => "4"})
      expect(e.to_s).to eq("Exception message: ws-man fault reason [message_id: 4]")
    end

    it "should prefer message to fault reason" do
      resp = {:message => "ws-man message", :reason => "ws-man fault reason", :message_id => "4"}
      e = ASM::WsMan::ResponseError.new("Exception message", resp)
      expect(e.to_s).to eq("Exception message: ws-man message [reason: ws-man fault reason, message_id: 4]")
    end
  end

  describe "#parse" do
    let(:connect_network_iso_response) { SpecHelper.load_fixture("wsman/connect_network_iso.xml") }
    let(:get_attach_status_response) { SpecHelper.load_fixture("wsman/get_attach_status.xml") }
    let(:fault_response) { SpecHelper.load_fixture("wsman/fault.xml") }
    let(:osd_concrete_job) { SpecHelper.load_fixture("wsman/osd_concrete_job.xml") }

    it "should parse simple responses" do
      expect(ASM::WsMan.parse(get_attach_status_response)).to eq({:return_value => "0"})
    end

    it "should parse job status responses" do
      expected = {:job => "DCIM_OSDConcreteJob:1",
                  :return_value => "4096"}
      expect(ASM::WsMan.parse(connect_network_iso_response)).to eq(expected)
    end

    it "should parse faults" do
      expected = {:code => "wsman:InvalidParameter",
                  :reason => "CMPI_RC_ERR_INVALID_PARAMETER",
                  :detail => "http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/MissingValues"}
      expect(ASM::WsMan.parse(fault_response)).to eq(expected)
    end

    it "should parse xsi:nil elements" do
      expected = {:delete_on_completion => "false",
                  :instance_id => "DCIM_OSDConcreteJob:1",
                  :job_name => "BootToNetworkISO",
                  :job_status => "Rebooting to ISO",
                  :message => nil,
                  :message_id => nil,
                  :name => "BootToNetworkISO"}
      expect(ASM::WsMan.parse(osd_concrete_job)).to eq(expected)
    end
  end

  describe "#detach_network_iso" do
    it "should invoke DetachIISOImage" do
      ASM::WsMan.expects(:invoke).with(endpoint, "DetachISOImage", ASM::WsMan::DEPLOYMENT_SERVICE_SCHEMA, :logger => logger)
      ASM::WsMan.detach_network_iso(endpoint, logger)
    end
  end

  describe "#boot to_network_iso" do
    it "should detach iso, wait for lc and boot network iso" do
      ASM::WsMan.expects(:detach_network_iso).with(endpoint, logger)
      ASM::WsMan.expects(:wait_for_lc_ready).with(endpoint, logger)
      ASM::WsMan.expects(:wait_for_iso_boot).with(endpoint, logger)
      props = {'IPAddress' => "rspec-ip",
               'ShareName' => "/var/rspec",
               'ShareType' => 0,
               'ImageName' => "rspec-microkernel.iso"}
      ASM::WsMan.expects(:invoke).with(endpoint, "BootToNetworkISO",
                                       ASM::WsMan::DEPLOYMENT_SERVICE_SCHEMA,
                                       :logger => logger, :props => props, :selector => '//n1:ReturnValue').returns("4096")
      ASM::WsMan.boot_to_network_iso(endpoint, "rspec-ip", logger, "rspec-microkernel.iso", "/var/rspec")
    end

    it "should fail with invalid response code" do
      ASM::WsMan.expects(:detach_network_iso).with(endpoint, logger)
      ASM::WsMan.expects(:wait_for_lc_ready).with(endpoint, logger)
      props = {'IPAddress' => "rspec-ip",
               'ShareName' => "/var/rspec",
               'ShareType' => 0,
               'ImageName' => "rspec-microkernel.iso"}
      ASM::WsMan.expects(:invoke).with(endpoint, "BootToNetworkISO",
                                       ASM::WsMan::DEPLOYMENT_SERVICE_SCHEMA,
                                       :logger => logger, :props => props, :selector => '//n1:ReturnValue').returns("FAIL")
      expect do
        ASM::WsMan.boot_to_network_iso(endpoint, "rspec-ip", logger, "rspec-microkernel.iso", "/var/rspec")
      end.to raise_error("Could not attach network ISO. Error code: FAIL")
    end
  end

  describe "#camel_case" do
    it "should not change single word" do
      expect(ASM::WsMan.camel_case("foo")).to eq("foo")
    end

    it "should capitalize 2nd word" do
      expect(ASM::WsMan.camel_case("foo_bar")).to eq("fooBar")
    end

    it "should capitalize 2nd and greater words" do
      expect(ASM::WsMan.camel_case("foo_bar_baz")).to eq("fooBarBaz")
    end

    it "should capitalize first letter if asked" do
      expect(ASM::WsMan.camel_case("foo_bar", :capitalize => true)).to eq("FooBar")
    end
  end

  describe "#snake_case" do
    it "should not change single word" do
      expect(ASM::WsMan.snake_case("foo")).to eq("foo")
    end

    it "should lower-case and add underscore before 2nd word" do
      expect(ASM::WsMan.snake_case("fooBar")).to eq("foo_bar")
    end

    it "should lower-case and add underscore before 2nd and greater words" do
      expect(ASM::WsMan.snake_case("fooBarBaz")).to eq("foo_bar_baz")
    end

    it "should not begin with an underscore if original did not" do
      expect(ASM::WsMan.snake_case("ReturnValue")).to eq("return_value")
    end

    it "should begin with an underscore if original value did" do
      expect(ASM::WsMan.snake_case("__cimnamespace")).to eq("__cimnamespace")
    end

    it "should treat multiple capitalized characters as a single word" do
      expect(ASM::WsMan.snake_case("JobID")).to eq("job_id")
    end

    it "should handle ISO as a single word" do
      expect(ASM::WsMan.snake_case("ISOAttachStatus")).to eq("iso_attach_status")
    end

    it "should handle fcoe and wwnn as single words" do
      expect(ASM::WsMan.snake_case("FCoEWWNN")).to eq("fcoe_wwnn")
    end

    it "should handle MAC as a single word" do
      expect(ASM::WsMan.snake_case("PermanentFCOEMACAddress")).to eq("permanent_fcoe_mac_address")
    end

  end

  describe "#enum_value" do
    it "should accept and convert keys to values" do
      expect(ASM::WsMan.enum_value(:share_type, {:foo => "a", :bar => "b"}, :foo)).to eq("a")
    end

    it "should accept values" do
      expect(ASM::WsMan.enum_value(:share_type, {:foo => "a", :bar => "b"}, "b")).to eq("b")
    end

    it "should fail for unknown values" do
      expect do
        ASM::WsMan.enum_value(:share_type, {:foo => "a", :bar => "b"}, :unknown)
        end.to raise_error("Invalid share_type value: unknown; allowed values are: :foo (a), :bar (b)")
    end
  end

  describe "#wsman_value" do
    it "should convert :share_type" do
      ASM::WsMan.expects(:enum_value).with(:share_type, {:nfs => "0", :cifs => "2"}, :cifs).returns("2")
      expect(ASM::WsMan.wsman_value(:share_type, :cifs)).to eq("2")
    end

    it "should convert :hash_type" do
      ASM::WsMan.expects(:enum_value).with(:hash_type, {:md5 => "1", :sha1 => "2"}, :md5).returns("1")
      expect(ASM::WsMan.wsman_value(:hash_type, :md5)).to eq("1")
    end

    it "should pass through other keys" do
      expect(ASM::WsMan.wsman_value(:foo, "foo")).to eq("foo")
    end
  end

  describe "#connect_network_iso_image" do
    it "should fail on missing parameters" do
      expect do
        ASM::WsMan.connect_network_iso_image(endpoint)
      end.to raise_error("Missing required parameter(s): ip_address, share_name, share_type, image_name")
    end

    it "should fail on unknown parameters" do
      expect do
        ASM::WsMan.connect_network_iso_image(stub("rspec-endpoint"),
                                             :ip_address => "172.0.0.1",
                                             :share_name => "/var/nfs",
                                             :share_type => :nfs,
                                             :image_name => "microkernel.iso",
                                             :bad_param => "foo")
      end.to raise_error("Unknown parameter(s): bad_param")
    end

    it "should invoke the wsman ConnectNetworkISOImage method" do
      ASM::WsMan.expects(:invoke).with(endpoint,
                                       "ConnectNetworkISOImage",
                                       ASM::WsMan::DEPLOYMENT_SERVICE_SCHEMA,
                                       :logger => logger,
                                       :props => {"IpAddress" => "172.0.0.1", "ShareName" => "/var/nfs",
                                                  "ShareType" => "0", "ImageName" => "microkernel.iso"},
                                       :selector => "//n1:ReturnValue").returns("4096")
      ASM::WsMan.connect_network_iso_image(endpoint,
                                           :ip_address => "172.0.0.1",
                                           :share_name => "/var/nfs",
                                           :share_type => :nfs,
                                           :image_name => "microkernel.iso",
                                           :logger => logger)
    end

    it "should fail if wsman returns an error code" do
      ASM::WsMan.expects(:invoke).with(endpoint,
                                       "ConnectNetworkISOImage",
                                       ASM::WsMan::DEPLOYMENT_SERVICE_SCHEMA,
                                       :logger => logger,
                                       :props => {"IpAddress" => "172.0.0.1", "ShareName" => "/var/nfs",
                                                  "ShareType" => "0", "ImageName" => "microkernel.iso"},
                                       :selector => "//n1:ReturnValue").returns("0")
      expect do
        ASM::WsMan.connect_network_iso_image(endpoint,
                                             :ip_address => "172.0.0.1",
                                             :share_name => "/var/nfs",
                                             :share_type => :nfs,
                                             :image_name => "microkernel.iso",
                                             :logger => logger)
      end.to raise_error("Could not connect network ISO. Error code: 0")
    end
  end
end
