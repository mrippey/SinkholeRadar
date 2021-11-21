# SinkholeRadar

SinkholeRadar was inspired by a 2020 blog post from The Vertex Project on automating the finding of sinkholes. 
After reading the post, I set out to create my own autmoation, as identifying possible malicious network infrastructure is 
a passion of mine. 

Upon running the script, the user will need to supply an IPv4 address, and that's it. The script will run its checks and return
any information that was found. 

If the user finds the possible sinkhole and its captured domains interesting, he/she can save the returned info to a MongoDB instance.

## Usage

python3 sinkholeradar.py
