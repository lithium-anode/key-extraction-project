# key-extraction-project
### Set up:
- Kali Linux Rolling
- Version: 2025.3
- Kernel version: 6.12.38

### Dependencies:
1. Open debug.list:
   `sudo nano /etc/apt/sources.list.d/debian-debug.list`
2. Add this line:
   `deb http://deb.debian.org/debian-debug/ sid-debug main`
3. Update apt pkg list:
   `sudo apt update`
4. Install debug symbols:
   `sudo apt install openssh-server-dbgsym`
5. Install gdb debugger:
   `sudo apt install gdb`
6. Confirm availabilty of debug symbols:
   ```
   sudo gdb /usr/lib/openssh/sshd-auth     # or /usr/lib/openssh/sshd-server
   (gdb) info functions kex_derive_keys    # displays function definintion in kex.c file
   (gdb) info functions do_authentication2 # displays function definintion in auth2.c file
   ```
7. Install bpftrace:
   `sudo apt install bpftrace`
8. Python dependencies:
   ```
   python3 -m venv venv_name         # Create a virtual environment
   source venv_name/bin/activate     # Activate venv_name
   pip3 install pycryptodome pyshark # Install libraries
   ```

### Run:
1. Start the SSH server:
   `sudo systemctl start ssh`
2. Start packet capture on Wireshark.
3. Run the file in the Scripts/ directory:
     - `sudo bpftrace monitor_kex.bt # to only see the extracted key`
     - `python3 listener.py          # for automatice network capture and decryption`
5. Connect to the server from the client device
