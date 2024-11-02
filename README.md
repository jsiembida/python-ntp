

### python-ntp

Pure python, clean room implementation of NTP client based directly on
[RFC5905](https://datatracker.ietf.org/doc/html/rfc5905).

* No extra dependencies, it is a single source file that works
  in vanilla Python 3.5 or newer.
* Tested to work on Linux, macOS and Windows.
* Any number of NTP servers can be used.
* NTP servers v4 and v3 are supported.
* And so are IPv4 and IPv6.
* The full suite of client side algorithms is implemented.
  From periodic polling of each peer, to finding consensus,
  to aggregate offset and jitter. Except the logic of correcting
  the local time, as this was never the goal. It still can
  be used to correct local system time, see the examples below.
* CLI offers functionality similar to [ntpdate(8)](https://linux.die.net/man/8/ntpdate),
  again, except the logic of setting the local time which can be worked around.


### API

Intended use is a thread running in a loop:

```
from time import sleep
from ntp import NtpArena, NtpUnsynchronizedError

# IPv4 of IPv6 addresses must be fed into NtpArena, hostnames must be resolved first.
ntp = NtpArena(addresses=["217.114.59.66", "82.69.171.134"])

while True:
    # query_peers returns the advisory pause before the next poll.
    # It handles network and NTP related errors.
    pause = ntp.query_peers()
    # calculate_state uses consensus algorithm to produce results.
    # It raises NtpUnsynchronizedError if it cannot.
    try:
        leap, offset, jitter = ntp.calculate_state()
        print(offset)
    except NtpUnsynchronizedError as e:
        print('problem:', e)
    sleep(max(1, pause))
```

Lower level API is exposed via `NtpMessage` and `NtpAssociation` classes.


### CLI

Keep running and showing NTP time every minute:

```
ntp.py --output-interval 60 pool.ntp.org time.nist.gov time.google.com time.apple.com
```

One shot run, returning offset between local and NTP time:

```
ntp.py --output-count 1 --output-format '{offset:+}' pool.ntp.org
```

Feeding the output to [date(1)](https://linux.die.net/man/1/date), in order to set
the system time. This is crude PLL logic, as in the clock discipline algorithm.

```
date --set="$(ntp.py --output-interval 30 --output-count 1 pool.ntp.org)"
```

Use `ntp.py --help` to learn more about available options.
