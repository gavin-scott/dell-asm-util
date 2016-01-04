# coding: utf-8
require "pathname"
require "asm/util"
require "rexml/document"
require "hashie"
require "nokogiri"
require "logger"
require "uri"
require "asm/wsman/client"
require "asm/wsman/parser"

module ASM
  class WsMan
    # rubocop:disable Metrics/LineLength
    BIOS_SERVICE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_BIOSService?SystemCreationClassName=DCIM_ComputerSystem,CreationClassName=DCIM_BIOSService,SystemName=DCIM:ComputerSystem,Name=DCIM:BIOSService"
    DEPLOYMENT_SERVICE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_OSDeploymentService?SystemCreationClassName=DCIM_ComputerSystem,CreationClassName=DCIM_OSDeploymentService,SystemName=DCIM:ComputerSystem,Name=DCIM:OSDeploymentService"
    JOB_SERVICE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_JobService?CreationClassName=DCIM_JobService,Name=JobService,SystemName=Idrac,SystemCreationClassName=DCIM_ComputerSystem"
    LC_SERVICE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_LCService?SystemCreationClassName=DCIM_ComputerSystem,CreationClassName=DCIM_LCService,SystemName=DCIM:ComputerSystem,Name=DCIM:LCService"
    LC_RECORD_LOG_SERVICE = "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_LCRecordLog?__cimnamespace=root/dcim"
    SOFTWARE_INSTALLATION_SERVICE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_SoftwareInstallationService?CreationClassName=DCIM_SoftwareInstallationService,SystemCreationClassName=DCIM_ComputerSystem,SystemName=IDRAC:ID,Name=SoftwareUpdate"
    # rubocop:enable Metrics/LineLength

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

    ### Enumeration methods

    def get_jobs
      client.enumerate("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_JobService")
    end

    def get_controller_views
      client.enumerate("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_ControllerView")
    end

    def get_virtual_disk_views
      client.enumerate("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_VirtualDiskView")
    end

    def get_physical_disk_views
      client.enumerate("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_PhysicalDiskView")
    end

    def get_fc_views
      client.enumerate("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/DCIM/DCIM_FCView")
    end

    def get_nic_views
      client.enumerate("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_NICView")
    end

    def get_bios_enumerations
      client.enumerate("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_BIOSEnumeration")
    end

    def get_boot_config_settings
      client.enumerate("http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_BootConfigSetting?__cimnamespace=root/dcim")
    end

    def get_boot_source_settings
      client.enumerate("http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_BootSourceSetting?__cimnamespace=root/dcim")
    end

    ### Get methods

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
    def get_deployment_job(job)
      client.get("http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_OSDConcreteJob", job)
    end

    def get_lc_job(job)
      client.get("http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_LifecycleJob", job)
    end

    ### Invoke Methods

    def create_reboot_job(params={})
      client.invoke("CreateRebootJob", SOFTWARE_INSTALLATION_SERVICE, :params => params,
                    :optional_params => [:reboot_start_time, :reboot_job_type],
                    :return_value => "4096")
    end

    def setup_job_queue(params={})
      client.invoke("SetupJobQueue", JOB_SERVICE, :params => params,
                    :optional_params => [:job_array, :start_time_interval, :until_time],
                    :return_value => "0")
    end

    # Special value of JID_CLEARALL deletes all jobs
    def delete_job_queue(params={})
      client.invoke("DeleteJobQueue", JOB_SERVICE, :params => params,
                    :optional_params => [:job_id],
                    :return_value => "0")
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
    def get_lc_status
      client.invoke("GetRemoteServicesAPIStatus", LC_SERVICE)
    end

    # Reboot server to a network ISO
    #
    # @note {detach_iso_image} should be called once the ISO is no longer needed.
    # @param options [Hash]
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
    # @raise [ASM::ResponseError] if the command fails
    def boot_to_network_iso_command(params={})
      client.invoke("BootToNetworkISO", DEPLOYMENT_SERVICE, :params => params,
                    :required_params => [:ip_address, :share_name, :share_type, :image_name],
                    :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                    :return_value => "4096")
    end

    # Connect a network ISO as a virtual CD-ROM
    #
    # The normal server boot order will be ignored after this call has been made.
    # The server will only boot into the network ISO until {disconnect_network_iso_image}
    # is called. The LC controller will be locked while the server is in this
    # state and no other LC jobs can be run.
    #
    # @note {disconnect_network_iso_image} should be called as soon as the ISO is not needed.
    # @param (see #boot_to_network_iso_command)
    # @return [Hash]
    # @raise [ASM::ResponseError] if the command fails
    def connect_network_iso_image_command(params={})
      client.invoke("ConnectNetworkISOImage", DEPLOYMENT_SERVICE, :params => params,
                    :required_params => [:ip_address, :share_name, :share_type, :image_name],
                    :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                    :return_value => "4096")
    end

    # Connect a network ISO from a remote file system
    #
    # The ISO will become available as a virtual CD boot option. In order to
    # boot off the ISO the normal server boot order must be separately configured.
    # Unlike {connect_network_iso_image}, this method will not lock the LC controller
    # and other LC jobs can be run as usual.
    #
    # @note {disconnect_rfs_iso_image} should be called as soon as the ISO is not needed.
    # @param (see #boot_to_network_iso_command)
    # @return [Hash]
    # @raise [ASM::ResponseError] if the command fails
    def connect_rfs_iso_image_command(params={})
      client.invoke("ConnectRFSISOImage", DEPLOYMENT_SERVICE, :params => params,
                    :required_params => [:ip_address, :share_name, :share_type, :image_name],
                    :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                    :return_value => "4096")
    end

    # Detach an ISO that was mounted with {boot_to_network_iso_command}
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def detach_iso_image
      client.invoke("DetachISOImage", DEPLOYMENT_SERVICE, :return_value => "0")
    end

    # Disconnect an ISO that was mounted with {connect_network_iso_image_command}
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def disconnect_network_iso_image
      client.invoke("DisconnectNetworkISOImage", DEPLOYMENT_SERVICE, :return_value => "0")
    end

    # Disconnect an ISO that was mounted with {connect_rfs_iso_image_command}
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def disconnect_rfs_iso_image
      client.invoke("DisconnectRFSISOImage", DEPLOYMENT_SERVICE, :return_value => "0")
    end

    def get_rfs_iso_image_connection_info
      client.invoke("GetRFSISOImageConnectionInfo", DEPLOYMENT_SERVICE)
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
    def get_attach_status
      client.invoke("GetAttachStatus", DEPLOYMENT_SERVICE)
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
    def get_network_iso_image_connection_info
      client.invoke("GetNetworkISOConnectionInfo", DEPLOYMENT_SERVICE)
    end

    def set_attributes(params={})
      client.invoke("SetAttributes", BIOS_SERVICE, :params => params,
                    :required_params => [:target, :attribute_name, :attribute_value],
                    :return_value => "0")
    end

    def create_targeted_config_job(params={})
      client.invoke("CreateTargetedConfigJob", BIOS_SERVICE, :params => params,
                    :required_params => [:target],
                    :optional_params => [:reboot_job_type, :scheduled_start_time, :until_time],
                    :return_value => "4096")
    end

    def change_boot_source_state(params={})
      client.invoke("ChangeBootSourceState",
                    "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_BootConfigSetting",
                    :params => params, :required_params => [:enabled_state, :source],
                    :url_params => :instance_id,
                    :return_value => "0")
    end

    def change_boot_order_by_instance_id(params={})
      client.invoke("ChangeBootOrderByInstanceID",
                    "http://schemas.dell.com/wbem/wscim/1/cim-schema/2/DCIM_BootConfigSetting",
                    :params => params, :required_params => :source,
                    :url_params => :instance_id,
                    :return_value => ["0", "4096"])
    end

    def import_system_configuration_command(params={})
      client.invoke("ImportSystemConfiguration", LC_SERVICE, :params => params,
                    :required_params => [:ip_address, :share_name, :file_name, :share_type],
                    :optional_params => [:target, :shutdown_type, :end_host_power_state, :username, :password],
                    :return_value => "4096")
    end

    def export_system_configuration_command(params={})
      client.invoke("ExportSystemConfiguration", LC_SERVICE, :params => params,
                    :required_params => [:ip_address, :share_name, :file_name, :share_type],
                    :optional_params => [:username, :password, :workgroup, :target, :export_use, :include_in_export],
                    :return_value => "4096")
    end

    def export_complete_lc_log(params={})
      client.invoke("ExportLCLog", LC_SERVICE, :params => params,
                    :required_params => [:ip_address, :share_name, :file_name, :share_type],
                    :optional_params => [:username, :password, :workgroup],
                    :return_value => "4096")
    end

    def get_config_results(params={})
      client.invoke("GetConfigResults", LC_RECORD_LOG_SERVICE,
                    :params => params,
                    :optional_params => [:instance_id, :job_id],
                    :return_value => "0")
    end

    ### Workflows

    def reboot(options={})
      options = {:reboot_job_type => :graceful_with_forced_shutdown,
                 :reboot_start_time => "TIME_NOW",
                 :timeout => 5 * 60}.merge(options)
      logger.info("Rebooting server %s" % host)
      resp = create_reboot_job(options)
      logger.info("Created reboot job %s on %s" % [resp[:reboot_job_id], host])
      setup_job_queue(:job_array => resp[:reboot_job_id],
                      :start_time_interval => "TIME_NOW", :logger => logger)
      logger.info("Waiting for reboot job %s to complete on %s" % [resp[:reboot_job_id], host])
      poll_lc_job(resp[:reboot_job_id], :timeout => 15 * 60, :logger => logger)
      logger.info("Successfully rebooted %s" % host)
      poll_for_lc_ready(options)
    end

    # Check the deployment job status until it is complete or times out
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param job [String] the job instance id
    # @param options [Hash]
    # @option options [Logger] :logger
    # @return [Hash]
    def poll_deployment_job(job, options={})
      options = {:timeout => 600}.merge(options)
      max_sleep_secs = 60
      resp = ASM::Util.block_and_retry_until_ready(options[:timeout], RetryException, max_sleep_secs) do
        resp = get_deployment_job(job)
        unless %w(Success Failed).include?(resp[:job_status])
          logger.info("%s status on %s: %s" % [job, host, Parser.response_string(resp)])
          raise(RetryException)
        end
        resp
      end
      raise(ASM::ResponseError.new("Deployment job %s failed" % job, resp)) unless resp[:job_status] == "Success"
      resp
    rescue Timeout::Error
      raise(Error, "Timed out waiting for job %s to complete. Final status: %s" % [job, Parser.response_string(resp)])
    end

    def poll_lc_job(job, options={})
      options = {:timeout => 600}.merge(options)
      max_sleep_secs = 60
      resp = ASM::Util.block_and_retry_until_ready(options[:timeout], RetryException, max_sleep_secs) do
        resp = get_lc_job(job)
        unless resp[:percent_complete] == "100" || resp[:job_status] =~ /complete/i
          logger.info("%s status on %s: %s" % [job, host, Parser.response_string(resp)])
          raise(RetryException)
        end
        resp
      end
      raise(ASM::ResponseError.new("LC job %s failed" % job, resp)) unless resp[:job_status] =~ /complete/i
      resp
    rescue Timeout::Error
      raise(Error, "Timed out waiting for job %s to complete. Final status: %s" % [job, Parser.response_string(resp)])
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
    def run_deployment_job(command, options={})
      options = {:timeout => 5 * 60}.merge(options)

      # LC must be ready for deployment jobs to succeed
      poll_for_lc_ready

      logger.info("Invoking %s with ISO %s on %s" % [command, options[:image_name], host])
      resp = client.invoke(command, DEPLOYMENT_SERVICE, :params => options,
                           :required_params => [:ip_address, :share_name, :share_type, :image_name],
                           :optional_params => [:workgroup, :user_name, :password, :hash_type, :hash_value, :auto_connect],
                           :return_value => "4096")

      logger.info("Initiated %s job %s on %s" % [command, resp[:job], host])
      resp = poll_deployment_job(resp[:job], :timeout => options[:timeout])
      logger.info("%s succeeded with ISO %s on %s: %s" % [command, options[:image_name], host, Parser.response_string(resp)])
    end

    # Connect network ISO image and await job completion
    #
    # @see {connect_network_iso_image_command}
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @param options [Hash]
    # @option options [Logger] :logger
    # @option options [FixNum] :timeout (5 minutes)
    # @return [Hash]
    def connect_network_iso_image(options={})
      options = {:timeout => 90}.merge(options)
      run_deployment_job("ConnectNetworkISOImage", options)
    end

    def connect_rfs_iso_image(options={})
      options = {:timeout => 90}.merge(options)
      resp = get_rfs_iso_image_connection_info
      if resp[:return_value] == "0"
        logger.info("Disconnecting old RFS ISO %s from %s" % [resp[:file_path], host])
        disconnect_rfs_iso_image
      end

      logger.info("Connecting RFS ISO %s to %s" % [options[:image_name], host])
      run_deployment_job("ConnectRFSISOImage", options)
    end

    # Boot to network ISO image and await job completion
    #
    # @see boot_to_network_iso_command
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @option options [Logger] :logger
    # @option options [FixNum] :timeout (5 minutes)
    # @return [Hash]
    def boot_to_network_iso_image(options={})
      options = {:timeout => 15 * 60}.merge(options)
      run_deployment_job("BootToNetworkISO", options)
    end

    # Wait for LC to be ready to accept new jobs
    #
    # If the server currently has a network ISO attached, it will be disconnected
    # as that will block LC from becoming ready.
    #
    # @param endpoint [Hash] the server connection details. See {invoke} endpoint hash.
    # @option options [FixNum] :timeout (5 minutes)
    # @return [Hash]
    def poll_for_lc_ready(options={})
      options = {:timeout => 5 * 60}.merge(options)

      resp = get_lc_status
      return if resp[:lcstatus] == "0"

      # If ConnectNetworkISOImage has been executed, LC will be locked until the image is disconnected.
      resp = get_network_iso_image_connection_info
      disconnect_network_iso_image if resp["image_name"]

      # Similarly, if BootToNetworkISO has been executed, LC will be locked until
      # the image is attached. Note that GetAttachStatus will return 1 both for
      # BootToNetworkISO and ConnectNetworkISOImage so it is important to check
      # ConnectNetworkISOImage first.
      resp = get_attach_status
      detach_iso_image if resp["iso_attach_status"] == "1"

      max_sleep_secs = 60
      resp = ASM::Util.block_and_retry_until_ready(options[:timeout], RetryException, max_sleep_secs) do
        resp = get_lc_status
        unless resp[:lcstatus] == "0"
          logger.info("LC status on %s: %s" % [host, Parser.response_string(resp)])
          raise(RetryException)
        end
        resp
      end
      logger.info("LC services are ready on %s" % host)
      resp
    rescue Timeout::Error
      raise(Error, "Timed out waiting for LC. Final status: %s" % Parser.response_string(resp))
    end

    def run_bios_config_job(options={})
      poll_for_lc_ready
      options = {:scheduled_start_time => "TIME_NOW",
                 :reboot_job_type => :graceful_with_forced_shutdown}.merge(options)
      resp = create_targeted_config_job(options)
      logger.info("Initiated BIOS config job %s on %s" % [resp[:job], host])
      resp = poll_lc_job(resp[:job])
      logger.info("Successfully set BootMode to Bios on %s: %s" % [host, Parser.response_string(resp)])
      logger.info("Waiting for LC ready on %s" % host)
      poll_for_lc_ready
    end

    def set_bios_attributes(attributes={})
      set_attributes(attributes)
      run_bios_config_job(attributes)
    end

    # NOTE: forces Bios boot (not uefi)
    def set_boot_order(boot_device, options={})
      boot_order_map = {:hdd => "Hard drive C: BootSeq", :virtual_cd => "Virtual Optical Drive BootSeq"}
      boot_device = Parser.enum_value("BootDevice", boot_order_map,
                                      boot_device, :strict => false)
      options = {:scheduled_start_time => "TIME_NOW",
                 :reboot_job_type => :graceful_with_forced_shutdown}.merge(options)

      logger.info("Waiting for LC ready on %s" % host)
      poll_for_lc_ready
      bios_enumerations = get_bios_enumeration
      boot_mode = bios_enumerations.find { |e| e[:attribute_name] == "BootMode" }
      raise("BootMode not found") unless boot_mode

      unless boot_mode[:current_value] == "Bios"
        # Set back to bios boot mode
        logger.info("Current boot mode on %s is %s, resetting to Bios BootMode" %
                        [host, boot_mode[:current_value]])
        set_bios_attributes(:target => boot_mode[:fqdd], :attribute_name => "BootMode",
                            :attribute_value => "Bios")
      end

      boot_settings = get_boot_source_settings
      target = boot_settings.find { |e| e[:element_name] == boot_device }
      unless target
        raise("Could not find %s boot device in current list: %s" %
                  [boot_device, boot_settings.map { |e| e[:element_name] }.join(", ")])
      end

      if target[:current_assigned_sequence] == "0" && target[:current_enabled_status] == "1"
        logger.info("%s is already configured to boot from %s" % [host, target[:element_name]])
        return
      end

      change_boot_order_by_instance_id(:instance_id => "IPL",
                                       :source => target[:instance_id])
      change_boot_source_state(:instance_id => "IPL", :enabled_state => 1,
                               :source => target[:instance_id])
      run_bios_config_job(:target => boot_mode[:fqdd],
                          :scheduled_start_time => options[:scheduled_start_time],
                          :reboot_job_type => options[:reboot_job_type])
    end

    def boot_rfs_iso_image(options={})
      options = {:reboot_job_type => :graceful_with_forced_shutdown,
                 :reboot_start_time => "TIME_NOW"}.merge(options)
      connect_rfs_iso_image(options)

      # Have to reboot in order for virtual cd to show up in boot source settings
      reboot(options)

      # Wait for virtual cd to show up in boot source settings
      timeout = 10 * 60
      max_sleep = 60
      virtual_cd_name = "Virtual Optical Drive BootSeq"
      ASM::Util.block_and_retry_until_ready(timeout, RetryException, max_sleep) do
        boot_settings = get_boot_source_settings
        found = boot_settings.find { |e| e[:element_name] == virtual_cd_name }
        raise(RetryException) unless found
      end

      set_boot_order(:virtual_cd)

    rescue Timeout::Error
      raise(Error, "Timed out waiting for %s to become available on %s" % [virtual_cd_name, host])
    end

    def import_system_configuration(params={})
      poll_for_lc_ready
      resp = import_system_configuration(params)
      poll_lc_job(resp[:job], :timeout => 30 * 60)
      poll_for_lc_ready
    end

    def export_system_configuration(params={})
      poll_for_lc_ready
      resp = export_system_configuration(params)
      poll_lc_job(resp[:job], :timeout => 5 * 60)
      poll_for_lc_ready
    end

    ### Deprecated methods

    def self.invoke(endpoint, method, schema, options={})
      WsMan.new(endpoint, options).invoke(method, schema, options)
    end

    def self.reboot(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Rebooting server #{host}") if logger
      wsman = ASM::WsMan.new(endpoint, :logger => logger)
      instanceid = invoke(endpoint, "CreateRebootJob",
                          SOFTWARE_INSTALLATION_SERVICE,
                          :selector => '//wsman:Selector Name="InstanceID"',
                          :props => {"RebootJobType" => "1"},
                          :logger => logger)

      # Execute job
      jobmessage = invoke(endpoint, "SetupJobQueue",
                          JOB_SERVICE,
                          :selector => "//n1:Message",
                          :props => {
                              "JobArray" => instanceid,
                              "StartTimeInterval" => "TIME_NOW"
                          },
                          :logger => logger)
      logger.debug "Job Message #{jobmessage}" if logger
      true
    end

    # @deprecated
    def self.poweroff(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Power off server #{host}") if logger

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

    # @deprecated
    def self.poweron(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Power on server #{host}") if logger

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

    # @deprecated
    def self.get_power_state(endpoint, logger=nil)
      # Create the reboot job
      logger.debug("Getting the power state of the server with iDRAC IP: #{host}") if logger
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

    # @deprecated
    def self.get_wwpns(endpoint, logger=nil)
      ASM::WsMan.new(endpoint, :logger => logger).get_fc_views.map { |e| e[:virtual_wwpn] }.compact
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
    # @deprecated
    def self.get_mac_addresses(endpoint, logger=nil)
      wsman = ASM::WsMan.new(endpoint, :logger => logger)
      bios_info = wsman.get_bios_enumerations
      ret = wsman.get_nic_views.inject({}) do |result, element|
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
      wsman = ASM::WsMan.new(endpoint, :logger => logger)
      bios_info = wsman.get_bios_enumerations
      ret = wsman.get_nic_views.inject({}) do |result, element|
        unless element[:fqdd].include?("Embedded")
          result[element[:fqdd]] = element[:permanent_mac_address] if is_usable_nic?(element, bios_info)
        end
        result
      end
      ret
    end

    # Gets LC status
    # @deprecated
    def self.lcstatus(endpoint, logger=nil)
      ASM::WsMan.new(endpoint, :logger => logger).get_lc_status.fetch(:lcstatus, nil)
    end

    # @deprecated Use {detach_iso_image} instead.
    def self.detach_network_iso(endpoint, logger=nil)
      ASM::WsMan.new(endpoint, :logger => logger).detach_iso_image
    end

    # @deprecated Use {boot_to_network_iso_image} instead.
    def self.boot_to_network_iso(endpoint, source_address, logger=nil, image_name="microkernel.iso", share_name="/var/nfs")
      options = {:ip_address => source_address,
                 :image_name => image_name,
                 :share_name => share_name,
                 :share_type => :nfs,
                 :logger => logger}
      ASM::WsMan.new(endpoint, :logger => logger).boot_to_network_iso_image(options)
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
          sleep 60
          wait_for_lc_ready(endpoint, logger, attempts + 1, max_attempts)
        end
      end
    end
  end
end
