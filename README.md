# Import OTX pulses as MISP event

Developped in a rush. Not really tested.
Import pulses to MISP using OTXv2 and PyMISP.


## Installation

``` sh
git clone https://github.com/LeHeron/otx_to_misp.git
cd otx_to_misp/
pip3 install -r REQUIREMENTS.txt
```


## Usage

To get help message :  
```sh
./otx -h
```  
Example running on local MISP instance :  
```sh
./otx -o "<OTX API KEY>" -m <MISP API KEY> -s "https://127.0.0.1 -t mytag1 -t mytag2"
```  

Use `-t <tag>` option multiple times to add tags  

If you are targeting a remote MISP server, add `-c` flag to check SSL certificate.  

New events are published by default. To disable it add `-n` flag
