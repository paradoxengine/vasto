#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################


###This module is awaiting fix after metasploit has been updated

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
    include REXML
  
	def initialize
		super(
			'Name'        => 'Xen Login Check Scanner',
			'Version'     => '1.0',
			'Description' => %q{
				This module will test a Xen login on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'      => ['Paolo Canaletti','Claudio Criscione'],
			'License'     => GPL_LICENSE
		)
		deregister_options('RHOST')
		deregister_options('RPORT')
		# does not work well with the current Msf::Auxiliary::AuthBrute... but nothing prevents you from trying in the future. Just delete this
		deregister_options('PASS_FILE')
		# does not work well with the current Msf::Auxiliary::AuthBrute... but nothing prevents you from trying in the future delete this
		deregister_options('USER_FILE')
		deregister_options('VHOST')
		
		register_options(
			[
				OptPort.new(	'RPORT',		[ true, "The target port (default 443)", 443 ]),
				OptBool.new(	'VERBOSE',		[ true, "Verbose output", false ]),
				OptString.new(	'passTest',		[ false, "Xen Password (only one)", ]),
				OptBool.new(	'SSL',			[ true, "Use SSL (default true)", true ]),
				OptString.new(	'userTest',		[ false, "Xen Username (only one)", ]),
			], self.class)

	end

	def run_host(ip)
		STDOUT.sync = true
		print_status("Starting host #{ip}")
		if (datastore["userTest"] and not datastore["userTest"].empty? or
			datastore["passTest"] and not datastore["passTest"].empty?)
			# then just do this user/pass
			try_user_pass(datastore["userTest"], datastore["passTest"], [datastore["userTest"],ip,rport].join(":"))
		else
			begin
				each_user_pass do |user, pass|
					this_cred = [user,ip,rport].join(":")
					next if self.credentials_good[this_cred]
					try_user_pass(user, pass, this_cred)
				end
		rescue Exception
			nil
			end
		end
	end

	def try_user_pass(user, pass, this_cred)
		
		xen_id = "there is a problem, the server don't send the opaqueRef"
		begin
			res = send_xen_request(rhost, user, pass)
			case res.code
			when 200
				xmldoc = Document.new(res.body)
				XPath.each(xmldoc, "//member/value") { |e| 
					case e.text
					when /Success/
						XPath.match(xmldoc, "//value").map {|x| 
							xen_id = x.text if( x.text =~ /OpaqueRef/ )
						}		
						report_conn_established(user, pass, this_cred, rhost, xen_id)
						print_good ("opaqueRef: #{xen_id}") if (datastore["VERBOSE"])
					when /Failure/
						report_conn_failed(user, pass, this_cred, rhost)
					end
				}
			when 500
				report_conn_error(rhost, user, pass, this_cred, 500)
			else
				print_status("Response Unreported: please send the output to p[dot]canaletti[at]securenetwork.it ... thanks!")
				puts "------------------\n#{res}\n------------------"
			end
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => rex_exep
			print_error "#{ rex_exep }"
		rescue ::Timeout::Error, ::Errno::EPIPE => other
			print_error "#{ other }"
		end
	end
	
def send_xen_request(ip, user, pass) 

	dataXen = "<?xml vrsion='1.0'?>
<methodCall>
<methodName>session.login_with_password</methodName>
<params>
<param>
<value><string>"+user+"</string></value>
</param>
<param>
<value><string>"+pass+"</string></value>
</param>
</params>
</methodCall>" 

	send_request_raw( {
		'method'  => 'POST',
		'data'    => dataXen,
		'headers' => {
			'Content-Length'  => dataXen.length,
			}
		}, -1)
end



def report_conn_established(user, pass, this_cred, ip, xen_id)

	print_good("#{ip} - LOGGED WITH SUCCESS \tuser: '#{user}' pass: '#{pass}' <===#")
	
	report_auth_info(
		:host	=> ip,
		:proto	=> 'HTTPS',
		:type	=> 'host.Xen.metasploit_login_bruteforcer',
		:user	=> user,
		:pass	=> pass,
		:targ_host	=> ip,
		:targ_port	=> datastore['RPORT'],
#		:data	=> {:satus => "#{xen_id}"}
		:sessionID	=> "#{xen_id}"
	)
	self.credentials_good[this_cred] = pass

end



def report_conn_failed(user, pass, this_cred, ip)
	print_error("#{ip} - Login Failed \tuser: \'#{user}\' pass: \'#{pass}\'") if (datastore["VERBOSE"])
	self.credentials_tried[this_cred] = pass
end



def report_conn_error(ip, user, pass, this_cred, err)
	
	print_error("#{ip} - Internal Server error: #{err} \tuser: \'#{user}\' pass: \'#{pass}\'") if (datastore["VERBOSE"])
	
	case err
	when 500
			report_note(
				:host	=> ip,
				:proto	=> 'HTTPS',
				:port   =>  datastore['RPORT'],
				:type   => 'host.Xen.metasploit_login_bruteforcer',
				:data   => {
					:user => user,
					:pass => pass,
					:status => "HTTP/1.1 500 - Internal Server Error."},
				:update => :unique_data
			)
		end
		self.credentials_tried[this_cred] = pass
	end

	
	
end



