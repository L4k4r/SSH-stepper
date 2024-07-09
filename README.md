# SSH-stepper
The code in this repository enables lateral movement through SSH connections by injecting keystrokes into a new SSH session, thus infecting an SSHD server to which the connection is being made. This tool is designed for red teaming operations where systems use short-lived or one-time passwords to connect via SSH. With this tool, it is still possible to achieve lateral movement through these secured connections.


# Backdoor
To use the backdoor, clone the [OpenSSH-Portable](https://github.com/openssh/openssh-portable) repository from Github and replace the `clientloop.c` and `channels.c` file with the files in the backdoor folder. 


Modify the `inject_keystrokes();` function at the end of the `clientloop.c` file to inject the desired command. Also, change the `channel_input_data();` function inside of the `channels.c` file, to filter out the desired command from the user's session.

Then proceed to build the binary:

```
autoreconf
./configure
make && make install
```

Now when executing the newly build SSH binary, the command(s) specified in the `inject_keystrokes();` function should be executed on the system the SSH connection is going to (sshd server).


# Injected malicious shared object
Instead of building the SSH binary with modified code, it is possible to inject a malicious shared object into the program and execute commands that way on the SSHD server. To do this, get the `ssh-stepper.c` file from the sharedobject folder, and compile it with:

```
gcc -fPIC -shared -o ssh-stepper.so ssh-stepper.c packet.o sshbuf.o sshbuf-getput-basic.o cipher.o *chacha*.o poly1305.o -ldl -pthread
```

Ensure to clone and build the original OpenSSH-Portable code, as the object files from that code are needed to compile the shared object.

Now, dynamically link the malicious shared object with the SSH program using `LD_PRELOAD`:

```
./LD_PRELOAD=./<path to malicious shared object> ssh <ip>
```
