# PingPlant

`PingPlant` is a Linux implant PoC that starts a custom listener for ICMP data, and parses the ethernet frame to check for a special payload.

If this payload is found, it will then initiate a callback to a defined IP.

Even though I have this connect back with a reverse shell, you could edit this to have it execute anything on the infected system when the special payload is received. Feel free to play around with this!


# Caveats

There is a functionality that will change the process name during initial run time. I've provided a generic name to hide this in most linux systems, called `[krfcommand]`

The way I got this to work, is that the original binary name needs to be the same amount of characters as this covert name. So if you're planning on using/testing this out, your binary name needs to be no longer than the covert one. 

For example `[krfcommand]` is 12 characters, so if your compiled binary name is 11 characters, this will work, if it's 12 or higher, it will not work. Play around with this to figure out the sweet spot.


# System artifacts

Though there is a neat feature to hide the actual binary name from the running proc list, `losf` and manually investigating the `/proc/<pid>/` directory will give away the fact that something fishy is going on. Whether that means this will get "caught" or if the running process will just get kicked, who knows? My thought about not doing much about that now, is that if there is someone going to that level of analysis, chances are something else was seen that made an investigation start.



# Build Instructions

```
go build -ldflags=-s -o <whatverYouWant> pingPlant.go
```

# Usage

Testing out this PoC is pretty easy. In one terminal, start a `nc` listener on whatever host and port you define (defaulted to localhost:8080):

```
nc -nvlp 8080
```

Now run the built binary in the background as root (don't call sudo, since this is will show up in the process tree with the real name of the binary)

```
sudo -s
./pingPlant &
```

At this point, the listener is active, and will be accepting "ICMP ECHO" packets. 

Finally, you can run the sender however you would like. There is much need to compile this, since this doesn't need to be as stealthy. This is included just so you can test out the functionality. 

```
go run pingSend.go
``` 


# Features

* Runtime process renaming
* No listening ports
* Written in Go, so almost all AV's will never pick this up


# TODO 

* Have the callback function automatically grab the IP from the machine calling in, to connect automagically
* Have this also try and hide /proc and `lsof` artifacts

# Demo

[![asciicast](https://asciinema.org/a/SvNWp9d8a6U3Zyz8WGhTns9Na.svg)](https://asciinema.org/a/SvNWp9d8a6U3Zyz8WGhTns9Na)
