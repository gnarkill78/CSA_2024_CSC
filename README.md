# CSA_2024_CSC
2024 ADF Cyber Skills Challenge Write-Ups

### Title of challenge here
Description - xxxxxxxxxxxxxxxxxxxxxxxxxxx
```
place any code here
```
Solution:
Plugged this straight into ChatGPT:
```
More code here for solution
```
:+1: FLAG{ENTER_FLAG_HERE}
<hr>

### Exfiltrate
Description - You as a forensic investigators responding to a data exfiltration attack on public safety infrastructure. By analyzing network logs, device activity, and traffic patterns, they must uncover the breach, identify compromised systems, and halt the exfiltration before more data is lost.

Flag Format: flag{7h1s_1s_4_fl4g}

Solution:
This was a log analysis challenge and required investigation of a pcap file

One of the first things in wireshark I do is check for objects that can be exported. In this, there were a large number of http objects.
![image](https://github.com/user-attachments/assets/2054de8d-4fa0-4f93-b07b-3664b62efa54)

The thing that stood out to me were the filenames of each object, based on their packet order. e.g.
```
?_=46
?_=4c
?_=41
?_=47
?_=7b
```
For those familiar with hex, this should be a stand out for seasoned CTFer's. It convers to FLAG{
This indicated that the filenames of each http object, in packet order, would reveal the flag.
How do we get these though without having to manually go through and write down each one??

Using tshark, we can extract the pcap file to json
```
tshark -r challenge.pcapng -Y "http" -T json > http_output.json
```
Then, using grep, we can print the strings that contain the filenames
```
grep 'http.response_for.uri": "http://4.240.83.28/?_=' http_output.json
```
This gives us the following output:
```
          "http.response_for.uri": "http://4.240.83.28/?_=46",
          "http.response_for.uri": "http://4.240.83.28/?_=4c",
          "http.response_for.uri": "http://4.240.83.28/?_=41",
          "http.response_for.uri": "http://4.240.83.28/?_=47",
          "http.response_for.uri": "http://4.240.83.28/?_=7b",
          "http.response_for.uri": "http://4.240.83.28/?_=49",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=64",
          "http.response_for.uri": "http://4.240.83.28/?_=30",
          "http.response_for.uri": "http://4.240.83.28/?_=6e",
          "http.response_for.uri": "http://4.240.83.28/?_=74",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=6b",
          "http.response_for.uri": "http://4.240.83.28/?_=6e",
          "http.response_for.uri": "http://4.240.83.28/?_=30",
          "http.response_for.uri": "http://4.240.83.28/?_=77",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=77",
          "http.response_for.uri": "http://4.240.83.28/?_=68",
          "http.response_for.uri": "http://4.240.83.28/?_=79",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=37",
          "http.response_for.uri": "http://4.240.83.28/?_=68",
          "http.response_for.uri": "http://4.240.83.28/?_=31",
          "http.response_for.uri": "http://4.240.83.28/?_=73",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=31",
          "http.response_for.uri": "http://4.240.83.28/?_=35",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=73",
          "http.response_for.uri": "http://4.240.83.28/?_=30",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=63",
          "http.response_for.uri": "http://4.240.83.28/?_=30",
          "http.response_for.uri": "http://4.240.83.28/?_=6d",
          "http.response_for.uri": "http://4.240.83.28/?_=6d",
          "http.response_for.uri": "http://4.240.83.28/?_=30",
          "http.response_for.uri": "http://4.240.83.28/?_=6e",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=77",
          "http.response_for.uri": "http://4.240.83.28/?_=34",
          "http.response_for.uri": "http://4.240.83.28/?_=59",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=74",
          "http.response_for.uri": "http://4.240.83.28/?_=30",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=54",
          "http.response_for.uri": "http://4.240.83.28/?_=72",
          "http.response_for.uri": "http://4.240.83.28/?_=61",
          "http.response_for.uri": "http://4.240.83.28/?_=6e",
          "http.response_for.uri": "http://4.240.83.28/?_=35",
          "http.response_for.uri": "http://4.240.83.28/?_=66",
          "http.response_for.uri": "http://4.240.83.28/?_=65",
          "http.response_for.uri": "http://4.240.83.28/?_=72",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=64",
          "http.response_for.uri": "http://4.240.83.28/?_=34",
          "http.response_for.uri": "http://4.240.83.28/?_=74",
          "http.response_for.uri": "http://4.240.83.28/?_=34",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=62",
          "http.response_for.uri": "http://4.240.83.28/?_=75",
          "http.response_for.uri": "http://4.240.83.28/?_=74",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=35",
          "http.response_for.uri": "http://4.240.83.28/?_=37",
          "http.response_for.uri": "http://4.240.83.28/?_=31",
          "http.response_for.uri": "http://4.240.83.28/?_=6c",
          "http.response_for.uri": "http://4.240.83.28/?_=6c",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=65",
          "http.response_for.uri": "http://4.240.83.28/?_=66",
          "http.response_for.uri": "http://4.240.83.28/?_=66",
          "http.response_for.uri": "http://4.240.83.28/?_=65",
          "http.response_for.uri": "http://4.240.83.28/?_=63",
          "http.response_for.uri": "http://4.240.83.28/?_=74",
          "http.response_for.uri": "http://4.240.83.28/?_=31",
          "http.response_for.uri": "http://4.240.83.28/?_=76",
          "http.response_for.uri": "http://4.240.83.28/?_=65",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=34",
          "http.response_for.uri": "http://4.240.83.28/?_=6e",
          "http.response_for.uri": "http://4.240.83.28/?_=64",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=57",
          "http.response_for.uri": "http://4.240.83.28/?_=31",
          "http.response_for.uri": "http://4.240.83.28/?_=64",
          "http.response_for.uri": "http://4.240.83.28/?_=65",
          "http.response_for.uri": "http://4.240.83.28/?_=6c",
          "http.response_for.uri": "http://4.240.83.28/?_=79",
          "http.response_for.uri": "http://4.240.83.28/?_=5f",
          "http.response_for.uri": "http://4.240.83.28/?_=75",
          "http.response_for.uri": "http://4.240.83.28/?_=53",
          "http.response_for.uri": "http://4.240.83.28/?_=65",
          "http.response_for.uri": "http://4.240.83.28/?_=64",
          "http.response_for.uri": "http://4.240.83.28/?_=7d",
          "http.response_for.uri": "http://4.240.83.28/?_=0a",
```
Taking it a little further, we can modify grep:
```
grep 'http.response_for.uri": "http://4.240.83.28/?_=' http_output.json | sed -E 's/.*_=(..).*/\1/' | tr '\n' ' '
```
Giving the result we're after
```
46 4c 41 47 7b 49 5f 64 30 6e 74 5f 6b 6e 30 77 5f 77 68 79 5f 37 68 31 73 5f 31 35 5f 73 30 5f 63 30 6d 6d 30 6e 5f 77 34 59 5f 74 30 5f 54 72 61 6e 35 66 65 72 5f 64 34 74 34 5f 62 75 74 5f 35 37 31 6c 6c 5f 65 66 66 65 63 74 31 76 65 5f 34 6e 64 5f 57 31 64 65 6c 79 5f 75 53 65 64 7d 0a
```
Plugging that into CyberChef reveals the flag

:+1: FLAG{I_d0nt_kn0w_why_7h1s_15_s0_c0mm0n_w4Y_t0_Tran5fer_d4t4_but_571ll_effect1ve_4nd_W1dely_uSed}
<hr>

### Traffic Light Protocol
Description - You work as a programmer in the traffic management office of our cities HQ. You have been informed that
there was a hacker in the system. Several systems have been altered and are now not working. You have
been tasked to restore the random traffic light algorithm to 100% efficiency. Flag Format:
flag{Ent3rYourf4agh3r3}

Solution:
nmap reveals that port 80 is open
```
└──╼ $nmap 10.0.254.102
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-22 21:11 UTC
Nmap scan report for 10.0.254.102
Host is up (0.018s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds
```
Viewing in a browser, we see:
```
Traffic Flow
Current Green Light:
trains
Currently Waiting Traffic:
Cars and buses, north and south side: 10
Cars and buses, east and west side: 10
Trains: 0
Pedestrians, east and west side: 10
Pedestrians, north and south side: 10
How To Control The Green Light
The green light can be adjusted through the following requests:

POST /carsBusesNorthSouth
POST /carsBusesEastWest
POST /trains
POST /pedestriansNorthSouth
POST /pedestriansEastWest
```
This is indicating the current traffic situation in the following sense:
* There is a current green light for the trains to move
* There are varying numbers of vehicles or pedestrains waiting at different sets of lights
* The lights can be changed by sending POST requests to different endpoints

Based on this, we can write some code to read where the current green light is, count the vehicles/pedestrains and change the lights to get traffic moving
```
import requests
from bs4 import BeautifulSoup
import time

# URLs for traffic light control
url_base = "http://10.0.254.102"
endpoints = {
    "carsBusesNorthSouth": "carsBusesNorthSouth",
    "carsBusesEastWest": "carsBusesEastWest",
    "trains": "trains",
    "pedestriansNorthSouth": "pedestriansNorthSouth",
    "pedestriansEastWest": "pedestriansEastWest"
}

label_to_endpoint = {
    "Cars and buses, north and south side:": "carsBusesNorthSouth",
    "Cars and buses, east and west side:": "carsBusesEastWest",
    "Trains:": "trains",
    "Pedestrians, east and west side:": "pedestriansEastWest",
    "Pedestrians, north and south side:": "pedestriansNorthSouth"
}

def get_waiting_traffic():
    try:
        response = requests.get(url_base)
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code}")
            return {}, None

        soup = BeautifulSoup(response.text, 'html.parser')

        # Check for flag-winning message
        flag_element = soup.find('h1')
        if flag_element:
            flag_text = flag_element.get_text(strip=True)
            if "flag{" in flag_text:
                print(f"🎉 You win! {flag_text}")
                exit(0)  # Exit the program after successfully capturing the flag

        # Extract the current green light
        current_green_element = soup.find('h2', string="Current Green Light:")
        if current_green_element:
            current_green = current_green_element.find_next_sibling(string=True).strip()
        else:
            print("Error: Couldn't find the 'Current Green Light:' section.")
            current_green = None

        # Extract waiting traffic numbers
        traffic = {}
        for label, endpoint in label_to_endpoint.items():
            element = soup.find(string=lambda text: text and label in text)
            if element:
                b_tag = element.find_next('b')
                if b_tag:
                    traffic[label] = int(b_tag.text)
                else:
                    print(f"Warning: Couldn't find <b> tag for {label}")
            else:
                print(f"Warning: Couldn't find label: {label}")

        return traffic, current_green

    except Exception as e:
        print(f"Error fetching or parsing traffic data: {e}")
        return {}, None


def post_green_light(direction):
    try:
        response = requests.post(f"{url_base}/{endpoints[direction]}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error posting green light: {e}")
        return False


def decide_green_light(traffic):
    return max(traffic, key=traffic.get, default=None)


def control_traffic():
    while True:
        traffic, current_green = get_waiting_traffic()
        if not traffic and current_green is None:
            print("No traffic data or current green light available. Retrying...")
            time.sleep(5)
            continue

        print("Traffic Data:", traffic)
        print("Current Green Light:", current_green)

        next_green = decide_green_light(traffic)
        if next_green and next_green != current_green:
            next_green_endpoint = label_to_endpoint.get(next_green)
            if next_green_endpoint:
                success = post_green_light(next_green_endpoint)
                if success:
                    print(f"Switched green light to {next_green}")
                else:
                    print(f"Failed to switch green light to {next_green}.")
            else:
                print(f"Error: No endpoint found for {next_green}")

        time.sleep(0.1)  # Prevent rapid switching


if __name__ == "__main__":
    control_traffic()
```
Here is a snippet of the output
```
Switched green light to Cars and buses, north and south side:
Traffic Data: {'Cars and buses, north and south side:': 2, 'Cars and buses, east and west side:': 2, 'Trains:': 2, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: carsBusesNorthSouth
Switched green light to Cars and buses, north and south side:
Traffic Data: {'Cars and buses, north and south side:': 2, 'Cars and buses, east and west side:': 2, 'Trains:': 2, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: carsBusesNorthSouth
Switched green light to Cars and buses, north and south side:
Traffic Data: {'Cars and buses, north and south side:': 1, 'Cars and buses, east and west side:': 2, 'Trains:': 2, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: carsBusesNorthSouth
Switched green light to Cars and buses, east and west side:
Traffic Data: {'Cars and buses, north and south side:': 1, 'Cars and buses, east and west side:': 2, 'Trains:': 2, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: carsBusesEastWest
Switched green light to Cars and buses, east and west side:
Traffic Data: {'Cars and buses, north and south side:': 1, 'Cars and buses, east and west side:': 1, 'Trains:': 2, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: carsBusesEastWest
Switched green light to Trains:
Traffic Data: {'Cars and buses, north and south side:': 1, 'Cars and buses, east and west side:': 1, 'Trains:': 2, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: trains
Switched green light to Trains:
Traffic Data: {'Cars and buses, north and south side:': 2, 'Cars and buses, east and west side:': 1, 'Trains:': 1, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: trains
Switched green light to Cars and buses, north and south side:
Traffic Data: {'Cars and buses, north and south side:': 2, 'Cars and buses, east and west side:': 1, 'Trains:': 1, 'Pedestrians, east and west side:': 2, 'Pedestrians, north and south side:': 2}
Current Green Light: carsBusesNorthSouth
Switched green light to Cars and buses, north and south side:
🎉 You win! You win! flag{8f9asdjk2jd9afjlz}
```
:+1: FLAG{8f9asdjk2jd9afjlz}
<hr>

### SSHielded
Description - Results of a recent security audit found that SSH is configured for password authentication. The root account is also permitted to login via password. Secure SSH on the device using the public and private keys provided.

Once completed the flag.txt will be located in the engineers home directory

SSH Credentials: engineer:papercloudmystic

Flag Format:flag{entering_your_flag}

Solution:
This challenge provides the public and private keys of the user 'engineer'

This is a hardening challenge and based on the description, we have to secure ssh access.

First thing to do is login as engineer and check whether this account can run any sudo commands
```
└──╼ $ssh engineer@10.0.255.200
The authenticity of host '10.0.255.200 (10.0.255.200)' can't be established.
ED25519 key fingerprint is SHA256:zvY/YgbGzL4h3C34FcKviaBhhXMxgElfy9N/NZOkJrA.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:10: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.255.200' (ED25519) to the list of known hosts.
engineer@10.0.255.200's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 5.15.0-119-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
engineer@SSHielded:~$ sudo -l
Matching Defaults entries for engineer on SSHielded:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User engineer may run the following commands on SSHielded:
    (ALL) NOPASSWD: /usr/sbin/service ssh reload
```
We can see from this that 'engineer' is allowed to reload the ssh service.
This supports the theory that it's an ssh hardening challenge.

Let's modify the login method for 'enginner' and set them up to use key authentication.

For this, I'l open a new terminal window, keeping my current login active.
We can also see that 'engineer' is not currently using ssh keys because there is no .ssh folder in their home folder
```
engineer@SSHielded:~$ ls -la
total 28
drwxr-x--- 1 engineer engineer 4096 Nov  4 03:35 .
drwxr-xr-x 1 root     root     4096 Nov  4 03:35 ..
-rw-r--r-- 1 engineer engineer  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 engineer engineer 3771 Mar 31  2024 .bashrc
drwx------ 2 engineer engineer 4096 Nov  4 03:35 .cache
-rw-r--r-- 1 engineer engineer  807 Mar 31  2024 .profile
```
In the new terminal window, I transfer the key to the remote server
```
└──╼ $ssh-copy-id engineer@10.0.255.200
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
engineer@10.0.255.200's password: 

Number of key(s) added: 1

Now try logging into the machine, with:   "ssh 'engineer@10.0.255.200'"
and check to make sure that only the key(s) you wanted were added.
```
Going back to the server, we can now see the .ssh directory
```
engineer@SSHielded:~$ ls -la
total 32
drwxr-x--- 1 engineer engineer 4096 Nov 24 06:46 .
drwxr-xr-x 1 root     root     4096 Nov  4 03:35 ..
-rw-r--r-- 1 engineer engineer  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 engineer engineer 3771 Mar 31  2024 .bashrc
drwx------ 2 engineer engineer 4096 Nov  4 03:35 .cache
-rw-r--r-- 1 engineer engineer  807 Mar 31  2024 .profile
drwx------ 2 engineer engineer 4096 Nov 24 06:46 .ssh
```
Now to test that the key pair is working
```
└──╼ $ssh engineer@10.0.255.200
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 5.15.0-119-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Nov 24 06:40:43 2024 from 192.168.0.105
```
Note, there was no request for a password.

We're still not there though since we haven't seen flag.txt in the engineers home directory.

Let's modify the sshd_config file to deny password authentication and deny the root user to login
```
vim /etc/ssh/sshd_config
```
Disable passwordauthentication

![image](https://github.com/user-attachments/assets/ffbec16d-2fd1-43bf-95e3-a21035ac78af)

Disable root account login

![image](https://github.com/user-attachments/assets/bc1eca6c-79a8-4dc3-be27-3caab58910f7)

Enable Public Key Authentication

![image](https://github.com/user-attachments/assets/c19ebec5-89f8-445f-8423-4b3cfbbe25e9)

Add authentication method

![image](https://github.com/user-attachments/assets/a40b168e-6e80-4420-84df-d18dfd8c1aee)

Save and close sshd_config then reload the ssh service
```
engineer@SSHielded:~$ sudo service ssh reload
 * Reloading OpenBSD Secure Shell server's configuration sshd                                 [ OK ] 
```

Once reloaded, execute 'ls' on the engineer's home directory and the flag should now be there
```
engineer@SSHielded:~$ ls
flag.txt
engineer@SSHielded:~$ cat flag.txt 
flag{securing_the_gate}
```
:+1: FLAG{securing_the_gate}
<hr>
