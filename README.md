# VulMap(Vulmon Mapper)
Find latest vulnerabilities and exploits on local host.

## Working Principle
* Get vulnerabilities and exploits that affects the host.
* Download a specific exploit or download all.

## Recommended Platform and Python Version
Vulmap currently only supports linux platforms and ![Python2](https://camo.githubusercontent.com/91573a399273230bbd7a6391aff545172fe49fb5/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f507974686f6e2d322d79656c6c6f772e737667).
* The recommended version for Python 2 is 2.7.x

* Run **deb** and **rpm** packages of linux.

## Installation
```
git clone https://github.com/ozelfatih/vulmap.git
```

Run the program with following command:
```
cd vulmap/
python vulmap.py -h
```

## Usage
Short Form | Long Form | Description
------------ | ------------- | -------------
-v | --verbose | Enable the verbose mode and display results in realtime
-d | --download | <exploit_id> to download a specific exploit
-a | --all_download | Download all found exploits 
-h | --help | Show the help message and exit

### Examples
* To list all the basic options and switches use -h switch:
```
python vulmap.py -h
```
* Normally mode:
```
python vulmap.py
```
* To enumerate package version's of local host and show the results in realtime:
```
python vulmap.py -v
```
* To download of specific exploit:
```
python vulmap.py -d <exploit_id>
```
* To download of all found exploits:
```
python vulmap.py -a
```

## License
Vulmap is licensed under the GNU GPL license. Take a look at the [LICENSE](https://github.com/ozelfatih/vulmap/blob/master/LICENSE) for more information.

## Version
Current version is 1.0
