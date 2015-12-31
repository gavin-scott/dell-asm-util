# coding: utf-8
require "pathname"
require "asm/util"
require "rexml/document"
require "hashie"
require "nokogiri"
require "logger"
require "uri"

module ASM
  module WsMan
    class Error < StandardError; end

    # Convert a wsman response hash into a human-readable string.
    #
    # @example
    #     response = {:message => "Could not connect to share", :code => "XXX", :return_value => "2"}
    #     ASM::WsMan.response_string(response) #=> "Could not connect to share [code: XXX, return_value: 2]"
    #
    # @api private
    # @param response [Hash] ws-man response as a Hash, i.e. after calling {#parse} on the response.
    # @return [String]
    def self.response_string(response)
      copy = response.dup
      message = copy.delete(:message)
      message = copy.delete(:reason) unless message
      message = copy.delete(:job_status) unless message
      ret = copy.keys.map { |k| "%s: %s" % [k, copy[k]]}.join(", ")
      ret = "%s [%s]" % [message, ret] if message
      ret
    end

    # An exception that encapsulates a ws-man response.
    class ResponseError < StandardError
      attr_reader :response

      def initialize(msg, response)
        super(msg)
        @response = response
      end

      def to_s
        "%s: %s" % [super.to_s, ASM::WsMan.response_string(response)]
      end
    end

    # rubocop:disable Metrics/LineLength
    BIOS_SERVICE_SCHEMA = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_BIOSService?SystemCreationClassName=DCIM_ComputerSystem,CreationClassName=DCIM_BIOSService,SystemName=DCIM:ComputerSystem,Name=DCIM:BIOSService"
    DEPLOYMENT_SERVICE_SCHEMA = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_OSDeploymentService?SystemCreationClassName=DCIM_ComputerSystem,CreationClassName=DCIM_OSDeploymentService,SystemName=DCIM:ComputerSystem,Name=DCIM:OSDeploymentService"
    JOB_SERVICE_SCHEMA = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_JobService?CreationClassName=DCIM_JobService,Name=JobService,SystemName=Idrac,SystemCreationClassName=DCIM_ComputerSystem"
    LC_SERVICE_SCHEMA = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_LCService?SystemCreationClassName=DCIM_ComputerSystem,CreationClassName=DCIM_LCService,SystemName=DCIM:ComputerSystem,Name=DCIM:LCService"
    SOFTWARE_INSTALLATION_SERVICE_SCHEMA = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_SoftwareInstallationService?CreationClassName=DCIM_SoftwareInstallationService,SystemCreationClassName=DCIM_ComputerSystem,SystemName=IDRAC:ID,Name=SoftwareUpdate"
    # rubocop:enable Metrics/LineLength

    # Invoke the wsman CLI cient
    #
    # Will automatically retry in the case of authentication errors.
    #
    # @param endpoint [Hash]
    # @option endpoint [String] :host the iDrac host
    # @option endpoint [String] :user the iDrac user
    # @option endpoint [String] :password the iDrac password
    # @param method the wsman method. Should be one of enumerate, get or a custom invoke method
    # @param schema the wsman schema
    # @param options [Hash]
    # @option options [String] :selector an xpath expression to run. Result will be returned as a String if there is one match, an Array of Strings otherwise.
    # @option options [Hash] :props arguments to an invoke command
    # @option options [String] :input_file an XML file containing options for an invoke command
    # @option options Logger] :logger logger for debug messages
    # @option options [FixNum] :nth_attempt used internally to allow recursive retry
    # rubocop:disable Metrics/MethodLength, Metrics/BlockNesting
    def self.invoke(endpoint, method, schema, options={})
      options = {
        :selector => nil,
        :props => {},
        :input_file => nil,
        :logger => nil,
        :nth_attempt => 0
      }.merge(options)

      unless options[:logger].nil? || options[:logger].respond_to?(:error)
        # The Puppet class has most of the methods loggers respond to except for error
        logger = options[:logger]
        def logger.error(msg)
          err(msg)
        end
      end

      if %w(enumerate get).include?(method)
        args = [method, schema]
      else
        args = ["invoke", "-a", method, schema]
      end

      args += ["-h", endpoint[:host],
               "-V", "-v", "-c", "dummy.cert", "-P", "443",
               "-u", endpoint[:user],
               "-j", "utf-8", "-m", "256", "-y", "basic", "--transport-timeout=300"]
      args += ["-J", options[:input_file]] if options[:input_file]
      options[:props].each do |key, val|
        args += ["-k", "#{key}=#{val}"]
      end

      if options[:logger]
        options[:logger].debug("Executing wsman #{args.join(' ')}")
      end
      result = ASM::Util.run_command_with_args("env", "WSMAN_PASS=#{endpoint[:password]}",
                                               "wsman", "--non-interactive", *args)
      options[:logger].debug("Result = #{result}") if options[:logger]

      # The wsman cli does not set exit_status properly on failure, so we
      # have to check stderr as well...
      unless result.exit_status == 0 && result.stderr.empty?
        if result["stdout"] =~ /Authentication failed/
          if options[:nth_attempt] < 2
            # We have seen sporadic authentication failed errors from idrac. Retry a couple times
            options[:nth_attempt] += 1
            options[:logger].info("Authentication failed, retrying #{endpoint[:host]}...") if options[:logger]
            sleep 10
            return invoke(endpoint, method, schema, options)
          end
          msg = "Authentication failed, please retry with correct credentials after resetting the iDrac at #{endpoint[:host]}."
        elsif result["stdout"] =~ /Connection failed./ || result["stderr"] =~ /Connection failed./
          if options[:nth_attempt] < 2
            # We have seen sporadic connection failed errors from idrac. Retry a couple times
            options[:nth_attempt] += 1
            options[:logger].info("Connection failed, retrying #{endpoint[:host]}...") if options[:logger]
            sleep 10
            return invoke(endpoint, method, schema, options)
          end
          msg = "Connection failed, Couldn't connect to server. Please check IP address credentials for iDrac at #{endpoint[:host]}."
        else
          msg = "Failed to execute wsman command against server #{endpoint[:host]}"
        end
        options[:logger].error(msg) if options[:logger]
        raise(Error, "#{msg}: #{result}")
      end

      if options[:selector]
        doc = REXML::Document.new(result["stdout"])
        options[:selector] = [options[:selector]] unless options[:selector].respond_to?(:collect)
        ret = options[:selector].collect do |selector|
          node = REXML::XPath.first(doc, selector)
          if node
            node.text
          else
            msg = "Invalid WS-MAN response from server #{endpoint[:host]}"
            options[:logger].error(msg) if options[:logger]
            raise(Error, msg)
          end
        end
        ret.size == 1 ? ret.first : ret
      else
        result["stdout"]
      end
    end
    # rubocop:enable Metrics/MethodLength, Metrics/BlockNesting

    # Parse a ws-man response element into a value
    #
    # Special-case handling exists for wsman:Selector responses which are used to
    # indicate job responses and for s:Subcode responses which are used in wsman faults.
    #
    # @api private
    # @param elem [Nokogiri::XML::Element]
    # @return [String]
    def self.parse_element(elem)
      if elem.namespaces.keys.include?("xmlns:wsman") && !(params = elem.xpath(".//wsman:Selector[@Name='InstanceID']")).empty?
        params.first.text
      elsif !(params = elem.xpath(".//s:Subcode")).empty? && params.children.size > 0
        params.children.map(&:text).join(", ")
      elsif elem.attributes["nil"] && elem.attributes["nil"].value == "true"
        nil
      else
        elem.text
      end
    end

    # Parse wsman response into a Hash
    #
    # @note currently does not work with enumerate responses
    # @api private
    # @param content [String] the response from calling {#invoke}
    # @return [Hash]
    def self.parse(content, require_body=true)
      doc = Nokogiri::XML.parse(content, &:noblanks)
      body = doc.search("//s:Body")
      unless body.children.size == 1
        raise("Unexpected WS-Man Body: %s" % body.children) if require_body
        return nil
      end
      ret = {}
      response = body.children.first
      response.children.each do |e|
        key = snake_case(e.name).to_sym
        ret[key] = parse_element(e)
      end
      ret
    end

    def self.parse_enumeration(content)
      responses = content.split("</s:Envelope>").map(&:strip).reject(&:empty?)

      # Check and return fault if found
      if responses.size == 1
        ret = parse(responses.first, false)
        return ret if ret
      end

      # Create an array of hashes containing each wsen:Item
      responses.flat_map do |xml|
        doc = Nokogiri::XML.parse(xml, &:noblanks)
        body = doc.search("//wsen:Items")
        next if body.children.empty?
        body.children.map do |elem|
          elem.children.inject({}) do |acc, e|
            key = snake_case(e.name).to_sym
            acc[key] = parse_element(e)
            acc
          end
        end
      end.compact
    end

    def self.reboot(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Rebooting server #{endpoint[:host]}") if logger
      instanceid = invoke(endpoint,
                          "CreateRebootJob",
                          SOFTWARE_INSTALLATION_SERVICE_SCHEMA,
                          :selector => '//wsman:Selector Name="InstanceID"',
                          :props => {"RebootJobType" => "1"},
                          :logger => logger)

      # Execute job
      jobmessage = invoke(endpoint,
                          "SetupJobQueue",
                          JOB_SERVICE_SCHEMA,
                          :selector => "//n1:Message",
                          :props => {
                            "JobArray" => instanceid,
                            "StartTimeInterval" => "TIME_NOW"
                          },
                          :logger => logger)
      logger.debug "Job Message #{jobmessage}" if logger
      true
    end

    def self.poweroff(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Power off server #{endpoint[:host]}") if logger

      power_state = get_power_state(endpoint, logger)
      if power_state.to_i != 13
        invoke(endpoint,
               "RequestStateChange",
               "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_ComputerSystem?CreationClassName=DCIM_ComputerSystem,Name=srv:system",
               :props => {"RequestedState" => "3"},
               :logger => logger)
      else
        logger.debug "Server is already powered off" if logger
      end
      true
    end

    def self.poweron(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Power on server #{endpoint[:host]}") if logger

      power_state = get_power_state(endpoint, logger)
      if power_state.to_i != 2
        invoke(endpoint,
               "RequestStateChange",
               "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_ComputerSystem?CreationClassName=DCIM_ComputerSystem,Name=srv:system",
               :props => {"RequestedState" => "2"},
               :logger => logger)
      else
        logger.debug "Server is already powered on" if logger
      end
      true
    end

    def self.get_power_state(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Getting the power state of the server with iDRAC IP: #{endpoint[:host]}") if logger
      response = invoke(endpoint,
                        "enumerate",
                        "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/DCIM_CSAssociatedPowerManagementService",
                        :logger => logger)
      updated_xml = response.scan(%r{(<\?xml.*?</s:Envelope>?)}m)
      xmldoc = REXML::Document.new(updated_xml[1][0])
      powerstate_node = REXML::XPath.first(xmldoc, "//n1:PowerState")
      powerstate = powerstate_node.text
      logger.debug("Power State: #{powerstate}") if logger
      powerstate
    end

    def self.get_fc_views(endpoint, options={})
      enumerate(endpoint, "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/DCIM/DCIM_FCView", options)
    end

    def self.get_wwpns(endpoint, logger=nil)
      get_fc_views(endpoint, :logger => logger).map { |e| e[:virtual_wwpn] }.compact
    end

    # Returns true if the NIC can be used in an ASM deployment, false otherwise.
    #
    # Criteria are:
    #
    # 1. NICs are excluded it their PermanentMACAddress is nil. Recent NIC / iDrac
    #    firmwares have started returning disabled NICs in the nic_view data, but
    #    their PermanentMACAddress will be nil.
    # 2. FQDD includes Embedded. Embedded NICs are not supported unless they are 57810
    # 3. Product is Broadcom 57800. These are 2x10Gb, 2x1Gb NICs
    # 4. NIC is not disabled in the BIOS.
    def self.is_usable_nic?(nic_info, bios_info)
      unsupported_embedded = nic_info[:fqdd].include?("Embedded") && !nic_info[:product_name].include?("57810")
      nic_info[:permanent_mac_address] && !nic_info[:permanent_mac_address].empty? &&
        !unsupported_embedded &&
        !nic_info[:product_name].match(/(Broadcom|QLogic).*5720/) &&
        !nic_status(nic_info[:fqdd], bios_info).match(/disabled/i)
    end

    def self.nic_status(fqdd, bios_info)
      fqdd_display = bios_display_name(fqdd)
      nic_enabled = "Enabled"
      bios_info.each do |bios_ele|
        if bios_ele[:attribute_display_name] == fqdd_display
          nic_enabled = bios_ele[:current_value]
          break
        end
      end
      nic_enabled
    end

    def self.bios_display_name(fqdd)
      display_name = fqdd
      fqdd_info = fqdd.scan(/NIC.(\S+)\.(\S+)-(\d+)-(\d+)/).flatten
      case fqdd_info[0]
      when "Mezzanine"
        display_name = "Mezzanine Slot #{fqdd_info[1]}"
      when "Integrated"
        display_name = "Integrated Network Card 1"
      when "Slot"
        display_name = "Slot #{fqdd_info[1]}"
      end
      display_name
    end

    # Return all the server MAC Address along with the interface location
    # in a hash format
    def self.get_mac_addresses(endpoint, logger=nil)
      bios_info = get_bios_enumeration(endpoint, :logger => logger)
      ret = get_nic_view(endpoint, :logger => logger).inject({}) do |result, element|
        result[element[:fqdd]] = select_mac_address(element) if is_usable_nic?(element, bios_info)
        result
      end
      ret
    end

    def self.select_mac_address(element)
      if element[:current_mac_address] != "00:00:00:00:00:00"
        element[:current_mac_address]
      elsif element[:permanent_mac_address]
        element[:permanent_mac_address]
      end
    end

    def self.get_permanent_mac_addresses(endpoint, logger=nil)
      bios_info = get_bios_enumeration(endpoint, :logger => logger)
      ret = get_nic_view(endpoint, :logger => logger).inject({}) do |result, element|
        unless element[:fqdd].include?("Embedded")
          result[element[:fqdd]] = element[:permanent_mac_address] if is_usable_nic?(element, bios_info)
        end
        result
      end
      ret
    end

    # Gets Nic View data
    def self.get_nic_view(endpoint, options={})
      schema = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_NICView"
      ret = enumerate(endpoint, schema, options)

      # Apparently we sometimes see a spurious empty return value...
      ret = enumerate(endpoint, schema, options) if ret.empty?

      ret
    end

    # Gets Nic View data
    def self.get_bios_enumeration(endpoint, options={})
      enumerate(endpoint, "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_BIOSEnumeration", options)
    end

    # Gets LC status
    def self.lcstatus(endpoint, logger=nil)
      invoke(endpoint, "GetRemoteServicesAPIStatus", LC_SERVICE_SCHEMA, :selector => "//n1:LCStatus", :logger => logger)
    end

    # Get the lifecycle controller (LC) status
    #
    # @example ready response
    #   {:lcstatus=>"0", :message=>"Lifecycle Controller Remote Services is ready.",
    #    :message_id=>"LC061", :rtstatus=>"0", :return_value=>"0", :server_status=>"2", :status=>"0"}
    #
    # @example busy response
    #   {:lcstatus=>"5", :message=>"Lifecycle Controller Remote Services is not ready.",
    #    :message_id=>"LC060", :rtstatus=>"1", :return_value=>"0", :server_status=>"1", :status=>"1"}
    #
    # An lcstatus of "0" indicates that the LC is ready to accept new jobs.
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @option options [Hash] :logger
    # @return [Hash]
    def self.get_lc_status(endpoint, options={})
      logger = options[:logger] || Logger.new(nil)
      resp = invoke(endpoint, "GetRemoteServicesAPIStatus", LC_SERVICE_SCHEMA, :logger => logger)
      parse(resp)
    end

    # Converts a ws-man parameter key into snake case
    #
    # Special case handling is included for various nouns that are usually (but
    # not always) capitalized such as ISO, MAC, FCOE, and WWNN>
    #
    # @param str [String] the wsman parameter key
    # @return [String]
    def self.snake_case(str)
      ret = str
      ret = ret.gsub(/ISO([A-Z]?)/) {|_e| "Iso%s" % $1}
      ret = ret.gsub(/MAC([A-Z]?)/) {|_e| "Mac%s" % $1}
      ret = ret.gsub(/FC[oO]E([A-Z]?)/) {|_e| "Fcoe%s" % $1}
      ret = ret.gsub(/WWNN([A-Z]?)/) {|_e| "Wwnn%s" % $1}
      ret = ret.gsub(/([A-Z]+)/) {|_e| "_%s" % $1.downcase}
      if ret =~ /^[_]+(.*)$/
        ret = $1
        ret = "%s%s" % [$1, ret] if str =~ /^([_]+)/
      end
      ret
    end

    # Search for the value in both the enum keys and values
    #
    # @param key [String] the enum name, used for error messaging only
    # @param enum [Hash] a hash of key/values. The values should be strings.
    # @param value [Object]
    # @return [String]
    # @raise [StandardError] if the value cannot be found in the enum
    def self.enum_value(key, enum, value)
      return enum[value] if enum[value]
      return value.to_s if enum.values.include?(value.to_s)
      allowed = enum.keys.map { |k| "%s (%s)" % [k.inspect, enum[k]]}.join(", ")
      raise("Invalid %s value: %s; allowed values are: %s" % [key.to_s, value, allowed])
    end

    # Convert known wsman properties to their expected format
    #
    # Converts known enum keys such as :share_type and :hash_type to their value.
    # Value is returned unmodified for other keys.
    #
    # @api private
    # @param key [Symbol] the property key, such as :share_type or :hash_type
    # @return [String]
    # @raise [StandardError] if an enum key has an unknown value
    def self.wsman_value(key, value)
      case key
      when :share_type
        enum_value(:share_type, {:nfs => "0", :cifs => "2"}, value)
      when :hash_type
        enum_value(:hash_type, {:md5 => "1", :sha1 => "2"}, value)
      else
        value
      end
    end

    # Convert string to camel case
    #
    # @api private
    # @param str [String]
    # @param options [Hash]
    # @option options [Boolean] :capitalize whether to capitalize the final result
    # @return [String]
    def self.camel_case(str, options={})
      options = {:capitalize => false}.merge(options)
      ret = str.gsub(/_(.)/) {|_e| $1.upcase}
      ret[0] = ret[0].upcase if options[:capitalize]
      ret
    end

    # Convert a symbol to a ws-man parameter key
    #
    # @api private
    # @param sym [Symbol]
    # @return [String]
    def self.param_key(sym)
      case sym
      when :ip_address
        "IPAddress"
      when :source
        "source"
      when :instance_id
        "InstanceID"
      else
        camel_case(sym.to_s, :capitalize => true)
      end
    end

    # TODO: document and test
    def self.invoke_service(endpoint, command, url, options={})
      options = options.dup
      url_params = Array(options.delete(:url_params))
      required_params = Array(options.delete(:required_params))
      optional_params = Array(options.delete(:optional_params))
      all_required = url_params + required_params
      missing_params = all_required.reject { |k| options.include?(k) }
      raise("Missing required parameter(s) for %s: %s" % [command, missing_params.join(", ")]) unless missing_params.empty?

      logger = options.delete(:logger) || Logger.new(nil)
      return_value = options.delete(:return_value)

      props = (required_params + optional_params).inject({}) do |acc, key|
        acc[param_key(key)] = wsman_value(key, options[key])
        acc
      end

      unless url_params.empty?
        encoded_arguments = url_params.map do |key|
          "%s=%s" % [URI.escape(param_key(key)), URI.escape(wsman_value(key, options[key]))]
        end.join("&")
        uri = URI(url)
        url = "%s%s%s" % [url, uri.query ? "&" : "?", encoded_arguments]
      end

      resp = invoke(endpoint, command, url, :logger => logger, :props => props)
      ret = parse(resp)
      raise(ResponseError.new("%s failed" % command, ret)) if return_value && ret[:return_value] != return_value
      ret
    end

    # Invoke a deployment ISO command
    #
    # DCIM_OSDeploymentService includes several commands that operate on ISO
    # images hosted on network shares that take the same parameters.
    #
    # @api private
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param command [String] the deployment command
    # @param options [Hash]
    # @option options [Logger] :logger a logger to use
    # @option options [String] :ip_address CIFS or NFS share IPv4 address. For example, 192.168.10.100. Required.
    # @option options [String] :share_name NFS or CIFS network share point. For example, "/home/guest" or "guest_smb.". Required.
    # @option options [String] :image_name ISO image name. Required.
    # @option options [String|Fixnum] :share_type share type. 0 or :nfs for NFS and 2 or :cifs for CIFS. Required.
    # @option options [String] :workgroup workgroup name, if applicable
    # @option options [String] :user_name user name, if applicable.
    # @option options [String] :password password, if applicable
    # @option options [String] :hash_type type of hash algorithm used to compute checksum: 1 or :md5 for MD5 and 2 or :sha1 for SHA1
    # @option options [String] :hash_value checksum value in string format computed using HashType algorithm
    # @option options [String] :auto_connect auto-connect to ISO image up on iDRAC reset
    # @return [Hash]
    # @raise [ResponseError] if the command fails
    def self.osd_deployment_invoke_iso(endpoint, command, options={})
      options = options.merge(:required_params => [:ip_address, :share_name, :share_type, :image_name],
                              :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                              :return_value => "4096")
      invoke_service(endpoint, command, DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Reboot server to a network ISO
    #
    # @note {detach_iso_image} should be called once the ISO is no longer needed.
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash] the ISO parameters. See {osd_deployment_invoke_iso} options hash.
    # @raise [ResponseError] if the command fails
    def self.boot_to_network_iso_command(endpoint, options={})
      options = options.merge(:required_params => [:ip_address, :share_name, :share_type, :image_name],
                              :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                              :return_value => "4096")
      invoke_service(endpoint, "BootToNetworkISO", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Connect a network ISO as a virtual CD-ROM
    #
    # The normal server boot order will be ignored after this call has been made.
    # The server will only boot into the network ISO until {disconnect_network_iso_image}
    # is called. The LC controller will be locked while the server is in this
    # state and no other LC jobs can be run.
    #
    # @note {disconnect_network_iso_image} should be called as soon as the ISO is not needed.
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash] the ISO parameters. See {osd_deployment_invoke_iso} options hash.
    # @raise [ResponseError] if the command fails
    def self.connect_network_iso_image_command(endpoint, options={})
      options = options.merge(:required_params => [:ip_address, :share_name, :share_type, :image_name],
                              :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                              :return_value => "4096")
      invoke_service(endpoint, "ConnectNetworkISOImage", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Connect a network ISO from a remote file system
    #
    # The ISO will become available as a virtual CD boot option. In order to
    # boot off the ISO the normal server boot order must be separately configured.
    # Unlike {connect_network_iso_image}, this method will not lock the LC controller
    # and other LC jobs can be run as usual.
    #
    # @note {disconnect_rfs_iso_image} should be called as soon as the ISO is not needed.
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash] the ISO parameters. See {osd_deployment_invoke_iso} options hash.
    # @raise [ResponseError] if the command fails
    def self.connect_rfs_iso_image_command(endpoint, options={})
      options = options.merge(:required_params => [:ip_address, :share_name, :share_type, :image_name],
                              :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                              :return_value => "4096")
      invoke_service(endpoint, "ConnectRFSISOImage", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Invoke a DCIM_DeploymentService command
    #
    # @api private
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param command [String]
    # @param options [Hash]
    # @option options [String] :return_value Expected ws-man return_value. An exception will be raised if this is not returned.
    # @return [Hash]
    def self.deployment_invoke(endpoint, command, options={})
      invoke_service(endpoint, command, DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Detach an ISO that was mounted with {boot_to_network_iso_command}
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def self.detach_iso_image(endpoint, options={})
      options = options.merge(:return_value => "0")
      invoke_service(endpoint, "DetachISOImage", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # @deprecated Use {detach_iso_image} instead.
    def self.detach_network_iso(endpoint, logger=nil)
      detach_iso_image(endpoint, :logger => logger)
    end

    # Disconnect an ISO that was mounted with {connect_network_iso_image_command}
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def self.disconnect_network_iso_image(endpoint, options={})
      options = options.merge(:return_value => "0")
      invoke_service(endpoint, "DisconnectNetworkISOImage", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Disconnect an ISO that was mounted with {connect_rfs_iso_image_command}
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def self.disconnect_rfs_iso_image(endpoint, options={})
      options = options.merge(:return_value => "0")
      invoke_service(endpoint, "DisconnectRFSISOImage", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Get current drivers and ISO connection status
    #
    # @example response
    #   {:drivers_attach_status=>"0", :iso_attach_status=>"1", :return_value=>"0"}
    #
    # The drivers and iso attach status will be reported as "0" for not attached
    # and "1" for "attached". The overall return_value will be non-zero if nothing
    # is currently attached.
    #
    # The ISO will show as attached if either {boot_to_network_iso_command} or
    # {connect_network_iso_image_command} have been executed.
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def self.get_attach_status(endpoint, options={})
      invoke_service(endpoint, "GetAttachStatus", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Get ISO image connection info
    #
    # @example response
    #   {:host_attached_status=>"1", :host_booted_from_iso=>"1",
    #    :ipaddr=>"172.25.3.100", :iso_connection_status=>"1",
    #    :image_name=>"ipxe.iso", :return_value=>"0", :share_name=>"/var/nfs"}
    #
    # The ISO attach status will be "0" for not attached and "1" for attached.
    #
    # The ISO will show as attached only if the {connect_network_iso_image_command}
    # has been executed.
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def self.get_network_iso_image_connection_info(endpoint, options={})
      invoke_service(endpoint, "GetNetworkISOConnectionInfo", DEPLOYMENT_SERVICE_SCHEMA, options)
    end

    # Get deployment job status
    #
    # @example response
    #   {:delete_on_completion => false, :instance_id => "DCIM_OSDConcreteJob:1",
    #    :job_name => "ConnectNetworkISOImage", :job_status => "Success",
    #    :message => "The command was successful", :message_id => "OSD1",
    #    :name => "ConnectNetworkISOImage"}
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param job [String] the job instance id
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def self.get_deployment_job(endpoint, job, options={})
      url = "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_OSDConcreteJob?InstanceID=%s" % job
      parse(invoke(endpoint, "get", url, :logger => options[:logger]))
    end

    class RetryException < StandardError; end

    # Check the deployment job status until it is complete or times out
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param job [String] the job instance id
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def self.poll_deployment_job(endpoint, job, options={})
      options = {:logger => Logger.new(nil), :timeout => 600}.merge(options)
      max_sleep_secs = 60
      resp = ASM::Util.block_and_retry_until_ready(options[:timeout], RetryException, max_sleep_secs) do
        resp = get_deployment_job(endpoint, job, :logger => options[:logger])
        unless %w(Success Failed).include?(resp[:job_status])
          options[:logger].info("%s status on %s: %s" % [job, endpoint[:host], response_string(resp)])
          raise(RetryException)
        end
        resp
      end
      resp
    rescue Timeout::Error
      raise(Error, "Timed out waiting for job %s to complete. Final status: %s" % [job, response_string(resp)])
    end

    # Execute a deployment ISO mount command and await job completion.
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param command [String] the ISO command, e.g. BootToNetworkISO or ConnectNetworkISOImage
    # @param job [String] the job instance id
    # @param options [Hash]
    # @option options [Logger] :logger
    # @option options [FixNum] :timeout (5 minutes)
    # @return [Hash]
    def self.run_deployment_job(endpoint, command, options={})
      options = {:timeout => 5 * 60}.merge(options)
      logger = options[:logger] || Logger.new(nil)

      # LC must be ready for deployment jobs to succeed
      poll_for_lc_ready(endpoint, :logger => logger)

      logger.info("Invoking %s with ISO %s on %s" % [command, options[:image_name], endpoint[:host]])
      options = options.merge(:required_params => [:ip_address, :share_name, :share_type, :image_name],
                              :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                              :return_value => "4096")
      resp = invoke_service(endpoint, command, DEPLOYMENT_SERVICE_SCHEMA, options)

      logger.info("Initiated %s job %s on %s" % [command, resp[:job], endpoint[:host]])
      resp = poll_deployment_job(endpoint, resp[:job], options)
      raise(ResponseError.new("%s job %s failed" % [command, resp[:job]], resp)) unless resp[:job_status] == "Success"
      logger.info("%s succeeded with ISO %s on %s: %s" % [command, options[:image_name], endpoint[:host], response_string(resp)])
    end

    # Connect network ISO image and await job completion
    #
    # @see {connect_network_iso_image_command}
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @option options [FixNum] :timeout (5 minutes)
    # @return [Hash]
    def self.connect_network_iso_image(endpoint, options={})
      options = {:timeout => 90}.merge(options)
      run_deployment_job(endpoint, "ConnectNetworkISOImage", options)
    end

    # Boot to network ISO image and await job completion
    #
    # @see boot_to_network_iso_command
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @option options [Logger] :logger
    # @option options [FixNum] :timeout (5 minutes)
    # @return [Hash]
    def self.boot_to_network_iso_image(endpoint, options={})
      options = {:timeout => 15 * 60}.merge(options)
      run_deployment_job(endpoint, "BootToNetworkISO", options)
    end

    # @deprecated Use {boot_to_network_iso_image} instead.
    def self.boot_to_network_iso(endpoint, source_address, logger=nil, image_name="microkernel.iso", share_name="/var/nfs")
      options = {:ip_address => source_address,
                 :image_name => image_name,
                 :share_name => share_name,
                 :share_type => :nfs,
                 :logger => logger}
      boot_to_network_iso_image(endpoint, options)
    end

    # Wait for LC to be ready to accept new jobs
    #
    # If the server currently has a network ISO attached, it will be disconnected
    # as that will block LC from becoming ready. Then poll the LC until it
    # reports a ready status.
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @option options [FixNum] :timeout (5 minutes)
    # @return [Hash]
    def self.poll_for_lc_ready(endpoint, options={})
      resp = get_lc_status(endpoint, :logger => options[:logger])
      return if resp[:lcstatus] == "0"

      # If ConnectNetworkISOImage has been executed, LC will be locked until the image is disconnected.
      resp = get_network_iso_image_connection_info(endpoint, :logger => logger)
      disconnect_network_iso_image(endpoint, options) if resp["image_name"]

      # Similarly, if BootToNetworkISO has been executed, LC will be locked until
      # the image is attached. Note that GetAttachStatus will return 1 both for
      # BootToNetworkISO and ConnectNetworkISOImage so it is important to check
      # ConnectNetworkISOImage first.
      resp = get_attach_status(endpoint, options)
      detach_iso_image(endpoint, options) if resp["iso_attach_status"] == "1"

      options = {:logger => Logger.new(nil), :timeout => 5 * 60}.merge(options)
      max_sleep_secs = 60
      resp = ASM::Util.block_and_retry_until_ready(options[:timeout], RetryException, max_sleep_secs) do
        resp = get_lc_status(endpoint, :logger => options[:logger])
        unless resp[:lcstatus] == "0"
          options[:logger].info("LC status on %s: %s" % [endpoint[:host], response_string(resp)])
          raise(RetryException)
        end
        resp
      end
      options[:logger].info("LC services are ready on %s" % endpoint[:host])
      resp
    rescue Timeout::Error
      raise(Error, "Timed out waiting for LC. Final status: %s" % response_string(resp))
    end

    # @deprecated Use {poll_for_lc_ready} instead.
    def self.wait_for_lc_ready(endpoint, logger=nil, attempts=0, max_attempts=30)
      if attempts > max_attempts
        raise(Error, "Life cycle controller is busy")
      else
        status = lcstatus(endpoint, logger).to_i
        if status == 0
          return
        else
          logger.debug "LC status is busy: status code #{status}. Waiting..." if logger
          sleep sleep_time
          wait_for_lc_ready(endpoint, logger, attempts + 1, max_attempts)
        end
      end
    end

    def self.sleep_time
      60
    end

    def self.enumerate(endpoint, url, options={})
      content = invoke(endpoint, "enumerate", url, :logger => options[:logger])
      resp = parse_enumeration(content)
      if resp.is_a?(Hash)
        klazz = URI.parse(url).split("/").last
        raise(ResponseError.new("%s enumeration failed" % klazz, resp))
      end
      resp
    end

    def self.get_boot_config_settings(endpoint, options={})
      enumerate(endpoint, "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_BootConfigSetting?__cimnamespace=root/dcim", options)
    end

    def self.get_boot_source_settings(endpoint, options={})
      enumerate(endpoint, "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_BootSourceSetting?__cimnamespace=root/dcim", options)
    end

    def self.create_targeted_config_job(endpoint, options={})
      invoke_service(endpoint, BIOS_SERVICE_SCHEMA, "CreateTargetedConfigJob", options)
    end

    def self.change_boot_source_state(endpoint, options={})
      options = options.merge(:required_params => [:enabled_state, :source], :url_params => :instance_id, :return_value => "4096")
      invoke_service(endpoint, "ChangeBootSourceState", "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_BootConfigSetting", options)
    end
  end
end
