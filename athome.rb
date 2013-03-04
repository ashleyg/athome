logs = "/home/pi/athome/logs/" #The directory to place logs in
arpscan = `arp-scan -lq`

#Bring in a list of users that we interested in
userList = File.read('users.txt')
names = []
macs  = []
userList.split("\n").map do |line|
    exploded = line.split(' ')
    names << exploded[0]
    macs << exploded[1] 
end

#Store the names that we detect are present
namesPresent = []
macs =
arpscan.split("\n").map do |line|
    if line =~ /([0-9A-F][0-9A-F :]{16})/i
        ipmacpair =  line.split(' ')
        #If the mac is in listed in the file of known macs
        if macs.include? ipmacpair[1]
            #Ping it to see if it's there
            pr = `ping #{ipmacpair[0]} -qc 3`
            
    	    #Go through the output of the ping command
            pr.split("\n").map do |pline|
                #Find the final line which contains packet loss information	
                if pline =~ /packet loss/
                    outcome =  pline.split(',')[3].split(' ')[0]
                    
                    #The outcome will be a percentage value if their has been packet loss
                    #otherwise it'll say time, so if that is present there is a good chance they're
                    #here.
                    if "time" == outcome
                        namesPresent << names[macs.index(ipmacpair[1])]
                    end
                 end
            end
        end
    end
end.compact.join(',')

puts "People Home"
puts namesPresent

#Output the state to the log directory
file = File.open(logs+Time.now.to_s,"w")
namesPresent.each do |name|
    file.write(name+"\n")
end
