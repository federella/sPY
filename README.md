# sPY

sPY is a basic osint script to find shodan devices and google cloud storage buckets matching the provided keyword.
More services will be likely added in the near future!

The script relies on the following:
- The [shodan](https://shodan.readthedocs.io/en/latest/tutorial.html#installation) python library. For this to work, you will need to provide a shodan API key, either through the `--key` switch or by creating a `config.yaml` file.
- A stripped-down version of the [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) library. The modified library will only test the identified buckets for _unauthenticated permissions_.

## Installation
To use the script, clone the repository and use [pip](https://pip.pypa.io/en/stable/) to install the required dependencies.

```bash
git clone https://github.com/federella/sPY.git
cd sPY/
pip3 install -r requirements.txt
```

## Usage

```
python s.py --help
            ,-.----.                
            \    /  \               
            |   :    \         ,---,
            |   |  .\ :       /_ ./|
  .--.--.   .   :  |: | ,---, |  ' :
 /  /    '  |   |   \ :/___/ \.  : |
|  :  /`./  |   : .   / .  \  \ ,' '
|  :  ;_    ;   | |`-'   \  ;  `  ,'
 \  \    `. |   | ;       \  \    ' 
  `----.   \:   ' |        '  \   | 
 /  /`--'  /:   : :         \  ;  ; 
'--'.     / |   | :          :  \  \
  `--'---'  `---'.|           \  ' ;
              `---`            `--` 
**************************************************
usage: s.py [-h] [--key [API_KEY]] [--out [OUTPUT]] keyword

Query Shodan for <keyword>

positional arguments:
  keyword          search keyword

optional arguments:
  -h, --help       show this help message and exit
  --key [API_KEY]  shodan api key [default: reads from config.yaml file]
  --out [OUTPUT]   output file [default: standard output]
```
