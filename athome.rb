require 'json'

logs = "./logs/" #The directory to place logs in

#Bring in a list of users that we interested in
puts "Loading Users"
userList = File.read('users.txt')
names = []
macs  = []
userList.split("\n").map do |line|
    exploded = line.split(' ')
    names << exploded[0]
    macs << exploded[1] 

    puts "User: "+exploded[0]+" Mac: "+exploded[1]
end

puts "\n\n"

puts "Running Scan"
arpscan = `sudo arp-scan -lq`
#Store the names that we detect are present
namesPresent = []
macs =
arpscan.split("\n").map do |line|
    puts line
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
puts "\n\n"

puts "People Home"
puts namesPresent
puts "\n\n"

# Prep the json string
resultsHash = {}
names.each do |name|
    tmpHash = {}
    if namesPresent.include? name
        tmpHash['present'] = true
        resultsHash[name] = tmpHash
    end
end
puts "Results Hash"
puts resultsHash

file_name = Time.now.to_s
File.open("logs/"+file_name,'w') do |f|
    f.write(resultsHash.to_json)
end
