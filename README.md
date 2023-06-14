# Import OTX pulses as MISP event

Developped in a rush. Not really tested.
Import pulses to MISP using OTXv2 and PyMISP.


## Installation

`git clone https://github.com/LeHeron/otx_to_misp.git`
`cd otx_to_misp/`
`pip3 install -r REQUIREMENTS.txt`

## Usage

To get help message :
`./otx -h`

Running on local MISP instance :
`./otx -o "<OTX API KEY>" -m <MISP API KEY> -s "https://127.0.0.1"`

If you are targeting a remote MISP server, add `-c` flag to check SSL certificate.
