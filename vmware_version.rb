#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary
  
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include REXML
  
  def initialize
    super(
      'Name'        => 'VMware Products Fingerprinter',
      'Version'     => '0.9',
      'Description' => 'Fingerprints a VMware Product, retrieving build and API versions.',
      'Author'      => [ 'Claudio Criscione','Paolo Canaletti'],
      'License'     =>  GPL_LICENSE
    )
    deregister_options('VHOST')
    register_options(
      [
	OptBool.new('VERBOSE',	[ true, "Print verbose info about the host", false ]),
	Opt::RPORT(443),
	OptBool.new('SSL',   [true, 'Use SSL', true])
      ], Auxiliary::Scanner)    
    
  end
  
  def run_host(ip)
    begin
      
    res = esx_query(ip)
    if res.code != 200 #Then try the converter
      res = converter_query(ip)    
    else #Then let's retrieve lang version
      lang = esx_lang(ip)
    end
       
    info = http_vmware_fingerprint(ip, res.body) #Extract version info 
    
    
    if(not datastore["VERBOSE"]) then
	  print_status("#{ip} is running: #{info[0]}, API Version #{info[5]}")
    else
	  print_status("#{ip} is running: #{info[0]}
	    API Version\t\t: #{info[4]}
	    OS type\t\t: #{info[5]}
	    locale Build\t\t: #{info[6]}
	    Locale Version\t: #{info[7]}
	    product Line ID\t: #{info[8]}
	    API type\t\t: #{info[9]}
	    Vendor\t\t: #{info[10]}")
    end

    print_status("#{ip} locale array: #{lang}")
    
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => rex_exep
      print_error "#{ rex_exep }"
    rescue ::Timeout::Error, ::Errno::EPIPE => other
      print_error "#{ other }"
    end
  end

  
  
 # Retrieve converter version
  def converter_query(ip)
    begin
      data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\"  xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"  xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"> <soapenv:Body> <ConverterRetrieveServiceContent xmlns=\"urn:converter\"><_this type=\"ConverterServiceInstance\">ServiceInstance</_this></ConverterRetrieveServiceContent> </soapenv:Body></soapenv:Envelope>"
      res = send_request_raw({
              'uri'     => '/converter/sdk',
              'method'  => 'POST',
              'vhost'   => ip,
              'data'    => data,
              'headers' =>
        {
                  'User-Agent'      => 'VMware-client/4.0.0',
                  'Content-Length'  => data.length,
                  'SOAPAction'      => 'urn:converter/1.0',
                  'Expect'          => '100-continue',
                  'Content-Type'    => 'text/xml; charset=\"UTF-8\"',
        }
      }, -1)
      return res
    end
  end
  
  #retrieve esx version
  def esx_query(ip)
    begin
      #Version 3, doesn't work on ESX4
      #data = "<?xml version=\"1.0\" encoding=\"utf-8\"?> <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">  <soap:Body>   <RetrieveServiceContent xmlns=\"urn:vim2\">             <_this type=\"ServiceInstance\">ServiceInstance</_this>   </RetrieveServiceContent>  </soap:Body> </soap:Envelope>"
      data = "<?xml version=\"1.0\" encoding=\"utf-8\"?> <soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">  <soap:Body>   <RetrieveServiceContent xmlns=\"urn:internalvim25\">    <_this type=\"ServiceInstance\">ServiceInstance</_this>   </RetrieveServiceContent>  </soap:Body> </soap:Envelope>"
      res = send_request_raw({
              'uri'     => '/sdk',
              'method'  => 'POST',
              'vhost'   => ip,
              'data'    => data,
              'headers' =>
        {
                  'User-Agent'      => 'VMware VI Client',
                  'Content-Length'  => data.length,
                  'SOAPAction'      => '\"\"',
                  'Expect'          => '100-continue',
                  'Content-Type'    => 'text/xml; charset=\"UTF-8\"',
        }
      }, -1)
      return res
    end
  end
  
  #Parses the result
  def http_vmware_fingerprint(ip, data)
    info = Array.new(11)
    doc = Document.new(data)
    about_elem = XPath.first( doc, "//about" )
	if(about_elem) then
															  #example:
	  info[0]  = about_elem.elements["fullName"].text         #VMware ESX Server 3i 3.5.0 build-184236
	  info[1]  = about_elem.elements["name"].text             #VMware ESX Server 3i
	  info[2]  = about_elem.elements["version"].text          #3.5.0
	  info[3]  = about_elem.elements["build"].text            #184236
	  info[4]  = about_elem.elements["osType"].text           #vmnix-x86
	  info[5]  = about_elem.elements["apiVersion"].text       #2.5u2
	  info[6]  = about_elem.elements["localeBuild"].text      #INTL
	  info[7]  = about_elem.elements["localeVersion"].text    #000
	  info[8]  = about_elem.elements["productLineId"].text    #embeddedEsx
	  info[9]  = about_elem.elements["apiType"].text          #HostAgent
	  info[10] = about_elem.elements["vendor"].text           #VMware, Inc.
	  
	  report_note(
	    :host	=> rhost,
		:port   =>  datastore['RPORT'],
		:type   => 'host.VMware.metasploit_fingerprint',
		:data   => {
		  :name				=> info[1],
		  :version			=> info[2],
		  :build			=> info[3],
		  :osType			=> info[4],
		  :apiVersion		=> info[5],
		  :localeBuild		=> info[6],
		  :localeVersion	=> info[7],
		  :productLineId	=> info[8],
		  :apiType			=> info[9],
		  :vendor			=> info[10]
		},
		:update => :unique_data
	  )
	end
    return info
  end
  
  
    
  #Retrieve esx lang
  def esx_lang(ip)
      data = '[{i:"1",exec:"/cmd/locales",args:[]}]'
      res = send_request_raw({
	    'uri'     => '/ui/sb',
	    'method'  => 'POST',
	    'vhost'   => ip,
	    'data'    => data,
	    'headers' =>
      {
		'Content-Length'  => data.length,
      }
      }, -1)
    return res.body
  end

  
end
