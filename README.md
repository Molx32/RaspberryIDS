# Raspberry Pi IDS
Raspberry Pi IDS is a university project which aims to plug a Raspberry Pi on a network, with a TAP, and centralize informations on a web dashboard.



## 1. Pre-requisites

### a. Download the Dash framework for Python
``` sh
$ pip intall dash
$ pip install dash-html-components
$ pip install dash-core-components
$ pip install dash-table-experiments
$ pip install pandas
```

### b. Install Snort
**Important**: the commands run in this part must be run as root (sudo -i).
#### Dependencies
##### Download and extract sources
Download Snort sources and DAQ sources, which is a dependency of Snort
- Download https://www.snort.org/downloads/snort/snort-2.9.12.tar.gz
- Download https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
Then uncompress the sources
``` sh
$ tar xvfz snort-2.9.12.tar.gz
$ tar xvfz daq-2.0.6.tar.gz
```
##### Install compilation packages
In order to compile we need to download the following packages
``` sh
Used for compilation
$ apt-get install bison -y
$ apt-get install flex -y
```

##### Install DAQ dependencies
In order to intall DAQ, we need to install a few dependencies
``` sh
$ apt-get install libpcap-dev -y
$ apt-get install libpcre3-dev -y
$ apt-get install libdumbnet -y
```

##### Install LuaJIT
It is possible the compilation fails because of a missing package named LuaJIT. Here is the package to install
``` sh
$ apt-get install libluajit-5.1
```

##### Install checkinstall
This program is used to verify other programs installations, and create packages
``` sh
$ apt-get install checkinstall
```

#### Daq Installation
Go into the *daq-2.0.6* folder and run the following commands.
``` sh
$ ./configure
$ make
```
The command **make** may fail. You simply need to re-run it until it works.

#### Snort Installation
Go into the *snort-2.9.12* folder and run the following commands.
``` sh
$ ./configure --enable-sourcefire
$ make
$ checkinstall -D --install=no --fstrans=no
$ dpkg -i snort_2.9.8.3-1_armhf.deb
```

Now Snort can be used.

## 2. Using Snort
We will be using Snort as a NIDS, so basically we will be having a logging directory and an alert file, and we will receive alerts in the alert file.

First, we create a logging directory:
``` sh
$ mkdir /home/pi/SNORT_LOG_FILE
``` 
Then, we configure the configuration file "snort.conf" (in my case it's installed in /home/pi/SNORT/snort-2.9.12/etc/snort.conf) as provided in the main repository. 
