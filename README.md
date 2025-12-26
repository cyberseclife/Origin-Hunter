# Origin-Hunter
A Program to find a target's real IP addresses NOT the IP they hide behind from their WAF but the actual server's IP that hosts that subdomain written in GoLang 

***This program is for use on authorized targets only! DO NOT  use on government entities unles you have explicit permission. The user assumes all liability during use. Hey, listen, I know nobody will adhere to this let alone read this but hey you know I gotta put it!*** 

Install Commands:
git clone https://github.com/cyberseclife/Origin-Hunter
cd Origin-Hunter
./origin-hunter
or gor Global Availability:
sudo cp /path/to/origin-hunter /user/local/bin/origin-hunter
or
sudo mv /path/to/origin-hunter /user/local/bin/origin-hunter
```
cyberseclife@debian-vm ~/Projects/origin-hunter $ ./origin-hunter -h

	   ___       _      _          _  _            _            
	  / _ \ _ _ (_)__ _(_)_ _     | || |_  _ _ __ | |_ ___ _ _  
	 | (_) | '_|| / _` | | ' \    | __ | || | '_ \|  _/ -_) '_| 
	  \___/|_|  |_\__, |_|_||_|   |_||_|\_,_|_| |_|\__\___|_|   
	              |___/                                         
Usage of ./origin-hunter:
  -A	Enable active scan (brute-force) (requires -w)
  -P	Enable passive scan (default) (requires -w) (default true)
  -f string
    	File containing list of targets
  -json
    	Save results in JSON format
  -l string
    	Comma-separated list of targets
  -o string
    	Output file to save results
  -r string
    	Custom DNS resolver (e.g. 8.8.8.8:53)
  -t int
    	Number of concurrent threads (default 20)
  -u string
    	Target URL/Domain (e.g. example.com)
  -v	Enable verbose output
  -w	Enable Wildcard/Enumeration mode (find subdomains)
