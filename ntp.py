#!/usr/bin/env python3


#   Copyright 2024 Jarek Siembida
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


#
# Pure Python, clean room implementation of NTP4 client.
#
# https://datatracker.ietf.org/doc/html/rfc5905
#


import logging
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address
from random import random
from socket import AF_INET, AF_INET6, SOCK_DGRAM
from socket import socket, getaddrinfo, gaierror
from struct import pack, unpack
from time import time, sleep


VERSION = 4
TOLERANCE = 15e-6  # 15 us/s (clock drift assumed in RFC)
PRECISION = -18  # 2**-18 s (again, this is assumed in RFC)
MINPOLL = 4  # 2**4 = 16 s
MAXPOLL = 14  # 2**14 = 4.5 h (RFC uses 17 instead of 14)
BADPOLL = 9   # 2**9 = 1 h
MAXDISP = 16  # 16 s
MINDISP = 0.005  # 5 ms
MAXDIST = 1
MAXSTRAT = 16
NSTAGE = 8
NMIN = 3
NOSYNC = 3


log = logging.getLogger("ntp")


def ntptime(t=None):
    if t is None:
        t = time()
    secs = int(t)
    frac = int(4294967296 * (t - secs))
    # Secs from 1900/01/01
    return secs + 2208988800, frac


class NtpError(Exception):
    pass


class NtpUnsynchronizedError(NtpError):
    pass


class NtpDeniedError(NtpError):
    pass


class NtpThrottledError(NtpError):
    pass


class NtpPacketError(NtpError):
    pass


class NtpMessage:
    def __init__(
        self,
        *,
        delay=MAXDISP,
        dispersion=MAXDISP,
        leap=NOSYNC,
        mode=3,
        poll=MINPOLL,
        precision=PRECISION,
        reference=b"",
        stratum=MAXSTRAT,
        t=None,
        t_dst=(0, 0),
        t_org=(0, 0),
        t_rec=(0, 0),
        t_ref=(0, 0),
        t_xmt=(0, 0),
        version=VERSION
    ):
        if t is None:
            t = time()

        self.delay = delay
        self.dispersion = dispersion
        self.leap = leap
        self.mode = mode
        self.poll = poll
        self.precision = precision
        self.reference = reference
        self.stratum = stratum
        self.t = t
        self.t_dst = t_dst
        self.t_org = t_org
        self.t_rec = t_rec
        self.t_ref = t_ref
        self.t_xmt = t_xmt
        self.version = version

    @staticmethod
    def to_short(x):
        # Page 13, short format is 32bit, unsigned, fixed point.
        if isinstance(x, int):
            return x & 0xffff, 0
        if isinstance(x, float):
            secs = int(x)
            frac = int(65536 * (x - secs))
            return secs & 0xffff, frac & 0xffff
        raise NtpError("Invalid NTP shot format value")

    @staticmethod
    def to_timestamp(x):
        # Page 13, timestamp is 64bit, unsigned, fixed point.
        if isinstance(x, int):
            return x & 0xffffffff, 0
        if isinstance(x, float):
            secs = int(x)
            frac = int(4294967296 * (x - secs))
            return secs & 0xffffffff, frac & 0xffffffff
        raise NtpError("Invalid NTP timestamp value")

    @staticmethod
    def from_short(secs, frac):
        return secs + frac / 65536

    @staticmethod
    def from_timestamp(secs, frac):
        return secs + frac / 4294967296

    def serialize(self):
        b1 = (
            ((self.leap & 3) << 6)
            | ((self.version & 7) << 3)
            | ((self.mode & 7) << 0)
        )
        delay_secs, delay_frac = self.to_short(self.delay)
        dispersion_secs, dispersion_frac = self.to_short(self.dispersion)
        t_ref_secs, t_ref_frac = self.t_ref
        t_org_secs, t_org_frac = self.t_org
        t_rec_secs, t_rec_frac = self.t_rec
        t_xmt_secs, t_xmt_frac = self.t_xmt
        reference_bytes = self.reference[:4].ljust(4, b"\0")

        return pack(
            "!BBbbHHHH4sLLLLLLLL",
            b1,
            self.stratum,
            self.poll,
            self.precision,
            delay_secs,
            delay_frac,
            dispersion_secs,
            dispersion_frac,
            reference_bytes,
            t_ref_secs,
            t_ref_frac,
            t_org_secs,
            t_org_frac,
            t_rec_secs,
            t_rec_frac,
            t_xmt_secs,
            t_xmt_frac,
        )

    @staticmethod
    def deserialize(b, t=None):
        if t is None:
            t = time()

        b = b[:48]
        if len(b) != 48:
            raise NtpPacketError("Invalid packet")

        (
            b1,
            stratum,
            poll,
            precision,
            delay_secs,
            delay_frac,
            dispersion_secs,
            dispersion_frac,
            reference_bytes,
            t_ref_secs,
            t_ref_frac,
            t_org_secs,
            t_org_frac,
            t_rec_secs,
            t_rec_frac,
            t_xmt_secs,
            t_xmt_frac,
        ) = unpack("!BBbbHHHH4sLLLLLLLL", b)

        leap = (b1 >> 6) & 3
        version = (b1 >> 3) & 7
        mode = (b1 >> 0) & 7

        if version != VERSION and version != 3:
            raise NtpPacketError("Invalid response version")

        if mode != 4:  # We only handle client - server use case.
            raise NtpPacketError("Invalid response mode")

        if stratum == 0:
            if reference_bytes == b"DENY" or reference_bytes == b"RSTR":
                raise NtpDeniedError
            if reference_bytes == b"RATE":
                raise NtpThrottledError

        if t_ref_secs == 0 and t_ref_frac == 0:
            raise NtpPacketError("Invalid t_ref in response")
        if t_rec_secs == 0 and t_rec_frac == 0:
            raise NtpPacketError("Invalid t_rec in response")
        if t_xmt_secs == 0 and t_xmt_frac == 0:
            raise NtpPacketError("Invalid t_xmt in response")

        return NtpMessage(
            delay=NtpMessage.from_short(delay_secs, delay_frac),
            dispersion=NtpMessage.from_short(dispersion_secs, dispersion_frac),
            leap=leap,
            mode=mode,
            poll=poll,
            precision=precision,
            reference=reference_bytes,
            stratum=stratum,
            t=t,
            t_dst=ntptime(t),
            t_org=(t_org_secs, t_org_frac),
            t_rec=(t_rec_secs, t_rec_frac),
            t_ref=(t_ref_secs, t_ref_frac),
            t_xmt=(t_xmt_secs, t_xmt_frac),
            version=version,
        )


class NtpState:
    def __init__(
        self,
        *,
        delay=MAXDISP,
        dispersion=MAXDISP,
        jitter=0,
        offset=0,
        t=None
    ):
        if t is None:
            t = time()

        self.delay = delay
        self.dispersion = dispersion
        self.jitter = jitter
        self.offset = offset
        self.t = t

    def __str__(self):
        return "offset=%g delay=%g dispersion=%g jitter=%g" % (
            self.offset,
            self.delay,
            self.dispersion,
            self.jitter,
        )


class NtpAssociation:
    def __init__(
        self,
        *,
        address,
        port=123,
        precision=PRECISION,
        tolerance=TOLERANCE,
        start_randomization=5.0,
        max_poll=None
    ):
        ip = ip_address(address)
        self.ipv6 = isinstance(ip, IPv6Address)
        self.address = (address, port)
        self.precision = precision
        self.tolerance = tolerance
        self.outgoing = None
        self.max_poll = max_poll
        t = time()
        self.incoming = NtpMessage(t=t)
        # RFC discusses reachability and timeouts. We don't do anything
        # special in this respect. Timeouts fill the register with dummy
        # stats. Which in turn makes the aggregate metrics degrade.
        # So all we do is select the peers that meet a fitness threshold.
        self.register = [NtpState(t=t) for _ in range(NSTAGE)]
        self.calculate_state(t)
        # Don't burst out all queries at once, randomize them within 5s.
        self.poll = MINPOLL
        self.poll_t = t + random() * start_randomization
        log.info("NTP association %s initialized", self)
        log.debug("%s Scheduled at %s", self, self.poll_t)

    def __hash__(self):
        return hash(self.address)

    def __eq__(self, other):
        if isinstance(other, NtpAssociation):
            return self.address == other.address
        if isinstance(other, tuple):
            return self.address == other
        return False

    def __str__(self):
        return "%s" % self.address[0]

    def __repr__(self):
        return self.__str__()

    def schedule_poll(self, delta, t=None):
        if t is None:
            t = time()

        if delta < 0:
            if self.poll < BADPOLL:
                # Still "ramping up", so keep doing it.
                self.poll = min(BADPOLL, self.poll - delta)
            else:
                # For failing queries, keep retrying more often
                # but no more often than at 2**BADPOLL intervals.
                self.poll = max(BADPOLL, self.poll + delta)
        elif delta > 0:
            self.poll = min(MAXPOLL, self.poll + delta)

        interval = 2 ** self.poll
        interval += random() * interval / 2 - interval / 4
        if self.max_poll is not None:
            interval = min(self.max_poll, interval)
        self.poll_t = t + interval
        log.debug("%s Scheduled at %s", self, self.poll_t)

    def calculate_state(self, t=None):
        if t is None:
            t = time()

        del self.register[:-NSTAGE]
        register = sorted(self.register, key=lambda x: x.delay)

        offset = register[0].offset
        delay = register[0].delay
        dispersion = sum(
            r.dispersion / (2 ** i) for i, r in enumerate(register, 1)
        )
        jitter = sum(
            (r.offset - offset) ** 2 for r in register
        ) / (len(register) - 1) ** 0.5

        self.state = NtpState(
            offset=offset,
            delay=delay,
            dispersion=dispersion,
            jitter=jitter,
            t=t,
        )

    def root_distance(self, t=None):
        if t is None:
            t = time()

        incoming = self.incoming
        state = self.state

        return (
            max(MINDISP, incoming.delay + state.delay) / 2
            + incoming.dispersion
            + state.dispersion
            + state.jitter
            + self.tolerance * abs(t - incoming.t)
        )

    def merit_factor(self, t=None):
        return self.incoming.stratum * MAXDIST + self.root_distance(t)

    def is_synchronized(self):
        incoming = self.incoming
        return (
            incoming.leap != NOSYNC
            and 0 < incoming.stratum < MAXSTRAT
            and incoming.delay / 2 + incoming.dispersion < MAXDISP
        )

    def is_fit(self, t=None):
        return self.is_synchronized() and self.root_distance(t) < MAXDISP

    def prepare_request(self, t=None):
        if t is None:
            t = time()

        self.outgoing = NtpMessage(
            t=t,
            t_org=self.incoming.t_xmt,
            t_rec=self.incoming.t_dst,
            t_xmt=ntptime(t),
            version=self.incoming.version,
        )
        return self.outgoing.serialize()

    def response_error(self, error, t=None):
        # Communication errors, including timeouts, cause degradation
        # of samples in the register and render the peer unfit.
        if t is None:
            t = time()

        log.info("%s Communication error: %s", self, error)

        self.outgoing = NtpMessage(
            t=t,
            t_xmt=(0, 0),
            version=self.incoming.version,
        )
        self.register.append(NtpState(t=t))
        self.calculate_state(t)
        self.schedule_poll(-1, t)

    def process_response(self, payload, t=None):
        if t is None:
            t = time()

        log.debug("%s Got a packet", self)

        try:
            r = NtpMessage.deserialize(payload, t)
            if r.t_org != self.outgoing.t_xmt:
                raise NtpPacketError("Bogus packet")
            if r.t_xmt == self.outgoing.t_org:
                # This should not really happen, as we zero t_xmt
                # and then dupes trigger "bogus packet" above.
                raise NtpPacketError("Duplicate packet")

            self.incoming = r
            self.outgoing = NtpMessage(
                t=t,
                t_org=self.incoming.t_xmt,
                t_rec=self.incoming.t_dst,
                t_xmt=(0, 0),
                version=self.incoming.version,
            )
            if not self.is_synchronized():
                raise NtpUnsynchronizedError("%s is not synchronized" % self)

            # RFC does the initial subtraction in integer arithmetics,
            # but we right away convert to FP64.
            # It still yields some 10us of precision given that seconds
            # from 1900 take 10 decimal digits.
            t1 = NtpMessage.from_timestamp(*r.t_org)
            t2 = NtpMessage.from_timestamp(*r.t_rec)
            t3 = NtpMessage.from_timestamp(*r.t_xmt)
            t4 = NtpMessage.from_timestamp(*r.t_dst)

            # Offset is the value we need to add to our local clock
            # in order, to be in sync with the peer. Therefore,
            # negative offset means our clock is running fast.
            offset = (t2 - t1 + t3 - t4) / 2
            delay = max(t4 - t1 - t3 + t2, 2 ** self.precision)
            dispersion = (
                2 ** r.precision
                + 2 ** self.precision
                + (t4 - t1) * self.tolerance
            )
            state = NtpState(
                offset=offset,
                delay=delay,
                dispersion=dispersion,
                t=t,
            )
            self.register.append(state)
            self.calculate_state(t)
            self.schedule_poll(1, t)
            log.debug("%s Update with %s", self, state)
        except NtpUnsynchronizedError:
            self.register.append(NtpState(t=t))
            self.calculate_state(t)
            self.schedule_poll(-1, t)
        except NtpError as e:
            self.schedule_poll(-1, t)
            log.info("%s %s", self, e.args[0])


class NtpArena:
    def __init__(
        self,
        *,
        addresses,
        socket_timeout=5.0,
        precision=PRECISION,
        tolerance=TOLERANCE,
        start_randomization=5.0,
        max_poll=None
    ):
        needs_ipv4 = False
        needs_ipv6 = False
        self.peers = {}
        for i in set(addresses):
            p = NtpAssociation(address=i,
                    precision=precision,
                    tolerance=tolerance,
                    start_randomization=start_randomization,
                    max_poll=max_poll)
            self.peers[p.address] = p
            if p.ipv6:
                needs_ipv6 = True
            else:
                needs_ipv4 = True

        if not needs_ipv4 and not needs_ipv6:
            raise ValueError("No IPv4/IPv6 addresses provided")

        self.sockv4 = None
        if needs_ipv4:
            self.sockv4 = socket(AF_INET, SOCK_DGRAM)
            self.sockv4.settimeout(socket_timeout)
            self.sockv4.bind(("0.0.0.0", 0))
            log.debug("Created IPv4 socket")

        self.sockv6 = None
        if needs_ipv6:
            self.sockv6 = socket(AF_INET6, SOCK_DGRAM)
            self.sockv6.settimeout(socket_timeout)
            self.sockv6.bind(("::", 0))
            log.debug("Created IPv6 socket")

    def query_peers(
        self,
        *,
        query_limit=None,
        time_limit=None,
        response_callback=None
    ):
        log.debug("Query peers")
        i = 0
        min_poll = 2 ** MINPOLL
        start = time()
        poll_q = sorted(self.peers.values(), key=lambda p: p.poll_t)
        # Polling loop:
        #   1. Choose the next peer.
        #   2. Send a query to it.
        #   3. Block the thread waiting for a reply.
        #   4. Process the reply.
        #   5. Go back to 1.
        # It is slow, but arguably offers the most precise timing of packets,
        # as there is nothing else involved apart from kernel sending the query
        # out and then waking the thread up as soon as the reply arrives.
        # Especially if that's the only active thread.
        for p in poll_q:
            i += 1
            if query_limit is not None and i > query_limit:
                log.debug("Query limit reached")
                return min_poll
            t = time()
            if time_limit is not None and t - start > time_limit:
                log.debug("Time limit reached")
                return min_poll
            diff = p.poll_t - t
            if diff > 1:
                log.debug("No more peers to query for now")
                return max(diff, min_poll)
            s = self.sockv6 if p.ipv6 else self.sockv4
            try:
                s.sendto(p.prepare_request(), p.address)
                while True:
                    payload, address = s.recvfrom(4096)
                    t = time()
                    if address[:2] == p:
                        p.process_response(payload, t)
                        if response_callback:
                            response_callback()
                        break
            except OSError as e:
                p.response_error(e)
        poll_q = sorted(self.peers.values(), key=lambda p: p.poll_t)
        return max(poll_q[0].poll_t - time(), min_poll)

    def filter_clocks(self, edges, low, high):
        # Truechimers have their midpoint in the found interval.
        truechimers = set()
        for e in edges:
            if e[2]:
                if low <= e[0] <= high:
                    truechimers.add(e[-1])

        if not truechimers:
            raise NtpUnsynchronizedError("No truechimers found")
        log.debug("Truechimers: %s", truechimers)

        while len(truechimers) > NMIN:
            min_jitter = None
            max_jitter = None
            max_jitter_peer = None
            for t in truechimers:
                offset = t.state.offset
                jitter = (
                    sum((p.state.offset - offset) ** 2 for p in truechimers)
                    / (len(truechimers) - 1)
                ) ** 0.5
                if min_jitter is None or min_jitter > t.state.jitter:
                    min_jitter = t.state.jitter
                if max_jitter is None or max_jitter < jitter:
                    max_jitter = jitter
                    max_jitter_peer = t
            if max_jitter < min_jitter:
                break
            truechimers.remove(max_jitter_peer)

        t = time()
        # First on the sorted list is our system peer
        survivors = sorted(truechimers, key=lambda p: p.merit_factor(t))
        log.debug("Survivors: %s", survivors)

        # Page 97, implements weighted average of survivors to produce
        # final offset and jitter. That's what is implemented here.
        weight = 0
        offset = 0
        jitter = 0
        leap_0 = survivors[0].incoming.leap
        # Convert the 3bit leap value to the extra second with sign.
        # Can be -1 (day is shorter by 1sec),
        # 0 (usual, no adjustment) or 1 (extra sec in the day).
        leap = -1 if leap_0 == 2 else leap_0
        offset_0 = survivors[0].state.offset
        for p in survivors:
            offset_p = p.state.offset
            weight_p = 1 / p.root_distance(t)
            weight += weight_p
            offset += offset_p * weight_p
            jitter += (offset_p - offset_0) ** 2 * weight_p

        offset /= weight
        jitter = (jitter / weight) ** 0.5
        log.debug("offset=%g jitter=%g leap=%d", offset, jitter, leap)
        return leap, offset, jitter

    def calculate_state(self):
        t = time()

        fit = [p for p in self.peers.values() if p.is_fit(t)]
        if not fit:
            raise NtpUnsynchronizedError("No fit peers found")
        log.debug("Fit peers: %s", fit)

        edges = []
        for p in fit:
            offset = p.state.offset
            distance = p.root_distance(t)
            edges.append((offset - distance, 1, 0, p))
            edges.append((offset, 0, 1, p))
            edges.append((offset + distance, -1, 0, p))

        edges.sort(key=lambda x: x[0])

        for i in range(max(1, len(fit) // 2)):
            log.debug("Finding consensus, assuming %d falsetickers", i)

            midpoints = 0
            low = None
            high = None

            count = 0
            for e in edges:
                count += e[1]
                if count >= len(fit) - i:
                    low = e[0]
                    break
                midpoints += e[2]

            count = 0
            for e in reversed(edges):
                count -= e[1]
                if count >= len(fit) - i:
                    high = e[0]
                    break
                midpoints += e[2]

            if (
                midpoints <= i
                and low is not None
                and high is not None
                and low < high
            ):
                return self.filter_clocks(edges, low, high)

        raise NtpUnsynchronizedError("No consensus found")


def argv_parser(progname=None):
    import argparse

    if progname is None:
        progname = "ntp"

    parser = argparse.ArgumentParser(
        prog=progname,
        formatter_class=argparse.RawTextHelpFormatter,
        description="Pure python NTP client",
        epilog="Example: %s --output-count 1 pool.ntp.org" % progname,
    )
    parser.add_argument(
        "server",
        nargs="+",
        help="NTP server(s) to query, can be addresses or hostnames.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["error", "warning", "info", "debug"],
        default="info",
    )
    parser.add_argument(
        "--output-count",
        type=int,
        default=0,
        help=(
            "how many times the output should be produced."
            " It defaults to zero, which means 'run forever'."
        )
    )
    parser.add_argument(
        "--output-interval",
        type=int,
        default=None,
        help=(
            "how often to produce the output (in seconds)."
            " Defaults to after each batch of queries."
            " Zero means after every reply from an NTP server."
            " Subject to availability of synchronization data."
        )
    )
    parser.add_argument(
        "--output-format",
        type=str,
        default="{Y:04}-{M:02}-{D:02}T{h:02}:{m:02}:{s:02}.{u:06}Z",
        help=(
            "defaults to '{Y:04}-{M:02}-{D:02}T{h:02}:{m:02}:{s:02}.{u:06}Z'"
            " Other variables available: count, offset, jitter, leap and time."
            " For example: 'offset={offset}'"
        )
    )
    parser.add_argument(
        "--socket-timeout",
        type=float,
        default=5.0,
        help="how long to wait for a reply from NTP server",
    )
    parser.add_argument(
        "--max-poll-interval",
        type=int,
        default=None,
        help=(
            "max interval between queries to each NTP server (in seconds)."
            " By default it is capped at 4.5h +/- 1h."
        )
    )
    return parser


def main():
    args = argv_parser().parse_args()
    log_level = getattr(logging, args.log_level.upper())
    output_format = args.output_format
    output_interval = args.output_interval
    output_count = max(0, args.output_count)
    output_t = time()
    output_i = 0

    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger().setLevel(log_level)

    def resolve(name):
        try:
            for i in getaddrinfo(name, 123):
                if i[0] == AF_INET or i[0] == AF_INET6:
                    yield i[-1][0]
        except gaierror as e:
            raise ValueError("Cannot resolve %s" % name) from e

    def output():
        nonlocal output_i, output_t
        try:
            leap, offset, jitter = ntp.calculate_state()
            t = time() + offset
            dt = datetime.fromtimestamp(t, timezone.utc)
            context = {
                "Y": dt.year,
                "M": dt.month,
                "D": dt.day,
                "h": dt.hour,
                "m": dt.minute,
                "s": dt.second,
                "u": dt.microsecond,
                "count": output_i + 1,
                "leap": leap,
                "time": t,
                "offset": offset,
                "jitter": jitter,
            }
            print(output_format.format_map(context), flush=True)
            output_i += 1
            if 0 < output_count <= output_i:
                raise StopIteration
            output_t = t
        except NtpUnsynchronizedError as e:
            output_t = time() + 3
            log.debug("%s", e)
        log.debug("Next output at %f", output_t)

    addresses = set()
    for i in args.server:
        addresses.update(resolve(i))
    ntp = NtpArena(
        addresses=addresses,
        socket_timeout=args.socket_timeout,
        max_poll=args.max_poll_interval,
    )

    time_limit = None
    if output_interval is not None and output_interval > 0:
        time_limit = output_interval
    response_callback = None
    if output_interval == 0:
        response_callback = output

    try:
        while output_count <= 0 or output_i < output_count:
            pause = ntp.query_peers(
                time_limit=time_limit,
                response_callback=response_callback,
            )
            if output_interval is None:
                output()
            elif output_interval > 0:
                current_t = time()
                if current_t - output_t >= output_interval:
                    output()
                pause = min(pause, output_interval - current_t + output_t)
            pause = min(max(pause, 1), 60)
            log.debug("Pause %f seconds", pause)
            sleep(pause)
    except StopIteration:
        pass


if __name__ == "__main__":
    main()
