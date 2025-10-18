# Copyright 2011,2012 James McCauley
# Copyright 2008 (C) Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
from .packet_utils import *
from .packet_utils import TruncatedException as Trunc
from .packet_base import packet_base

from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

rrtype_to_str = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA",
    7: "MB", 8: "MG", 9: "MR", 10: "NULL", 11: "WKS", 12: "PTR",
    13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT", 28: "AAAA"
}

rrclass_to_str = {
    1: "IN", 2: "CS", 3: "CH", 4: "HS", 255: "*"
}


class dns(packet_base):
    "DNS Packet struct"

    MDNS_ADDRESS = IPAddr('224.0.0.251')
    MDNS6_ADDRESS = IPAddr6('ff02::fb')
    MDNS_ETH = EthAddr('01:00:5E:00:00:fb')
    MDNS6_ETH = EthAddr('33:33:00:00:00:fb')

    SERVER_PORT = 53
    MDNS_PORT = 5353
    MIN_LEN = 12

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)
        self.prev = prev

        self.questions = []
        self.answers = []
        self.authorities = []
        self.additional = []

        self.id = 0
        self.qr = False
        self.opcode = 0
        self.aa = False
        self.tc = False
        self.rd = False
        self.ra = False
        self.z = False
        self.ad = False
        self.cd = False
        self.rcode = 0

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def _exc(self, e, part=None):
        msg = "(dns)"
        if part is not None:
            msg += " " + part
        msg += ": " + str(e)
        if isinstance(e, Trunc):
            self.msg(msg)
        else:
            self.err(msg)

    def hdr(self, payload):
        bits0 = 0
        if self.qr: bits0 |= 0x80
        bits0 |= (self.opcode & 0x7) << 4
        if self.rd: bits0 |= 1
        if self.tc: bits0 |= 2
        if self.aa: bits0 |= 4
        bits1 = 0
        if self.ra: bits1 |= 0x80
        if self.z: bits1 |= 0x40
        if self.ad: bits1 |= 0x20
        if self.cd: bits1 |= 0x10
        bits1 |= (self.rcode & 0xf)

        s = struct.pack("!HBBHHHH", self.id, bits0, bits1,
                        len(self.questions), len(self.answers),
                        len(self.authorities), len(self.additional))

        def makeName(labels, term):
            o = ''
            for l in labels.split('.'):
                o += chr(len(l))
                o += l
            if term: o += '\x00'
            return o

        name_map = {}

        def putName(s, name):
            pre = ''
            post = name
            while True:
                at = s.find(makeName(post, True))
                if at == -1:
                    if post in name_map:
                        at = name_map[post]
                if at == -1:
                    post = post.split('.', 1)
                    if pre: pre += '.'
                    pre += post[0]
                    if len(post) == 1:
                        if len(pre) == 0:
                            s += '\x00'
                        else:
                            name_map[name] = len(s)
                            s += makeName(pre, True)
                        break
                    post = post[1]
                else:
                    if len(pre) > 0:
                        name_map[name] = len(s)
                        s += makeName(pre, False)
                    s += struct.pack("!H", at | 0xc000)
                    break
            return s

        def putData(s, r):
            if r.qtype in (2, 12, 5, 15):  # NS, PTR, CNAME, MX
                return putName(s, r.rddata)
            elif r.qtype == 1:  # A
                assert isinstance(r.rddata, IPAddr)
                return s + r.rddata.raw
            elif r.qtype == 28:  # AAAA
                assert isinstance(r.rddata, IPAddr6)
                return s + r.rddata.raw
            else:
                return s + r.rddata

        for r in self.questions:
            s = putName(s, r.name)
            s += struct.pack("!HH", r.qtype, r.qclass)

        rest = self.answers + self.authorities + self.additional
        for r in rest:
            s = putName(s, r.name)
            s += struct.pack("!HHIH", r.qtype, r.qclass, r.ttl, 0)
            fixup = len(s) - 2
            s = putData(s, r)
            fixlen = len(s) - fixup - 2
            s = s[:fixup] + struct.pack('!H', fixlen) + s[fixup+2:]

        return s

    def parse(self, raw):
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < dns.MIN_LEN:
            self.msg('(dns) packet data too short to parse header: data len %u' % (dlen,))
            return None

        (self.id, bits0, bits1, total_questions, total_answers,
         total_auth_rr, total_add_rr) = struct.unpack('!HBBHHHH', raw[:12])

        self.qr = True if (bits0 & 0x80) else False
        self.opcode = (bits0 >> 4) & 0x07
        self.aa = True if (bits0 & 0x04) else False
        self.tc = True if (bits0 & 0x02) else False
        self.rd = True if (bits0 & 0x01) else False
        self.ra = True if (bits1 & 0x80) else False
        self.z = True if (bits1 & 0x40) else False
        self.ad = True if (bits1 & 0x20) else False
        self.cd = True if (bits1 & 0x10) else False
        self.rcode = bits1 & 0x0f

        query_head = 12

        # questions
        for _ in range(total_questions):
            try:
                query_head = self.next_question(raw, query_head)
            except Exception as e:
                self._exc(e, 'parsing questions')
                return None

        # answers
        for _ in range(total_answers):
            try:
                query_head = self.next_rr(raw, query_head, self.answers)
            except Exception as e:
                self._exc(e, 'parsing answers')
                return None

        # authoritative name servers
        for _ in range(total_auth_rr):
            try:
                query_head = self.next_rr(raw, query_head, self.authorities)
            except Exception as e:
                self._exc(e, 'parsing authoritative name servers')
                return None

        # additional resource records
        for _ in range(total_add_rr):
            try:
                query_head = self.next_rr(raw, query_head, self.additional)
            except Exception as e:
                self._exc(e, 'parsing additional resource records')
                return None

        self.parsed = True

    @classmethod
    def _read_dns_name_from_index(cls, l, index, retlist):
        try:
            while True:
                chunk_size = l[index] if isinstance(l[index], int) else ord(l[index])
                if (chunk_size & 0xc0) == 0xc0:
                    offset = ((l[index] & 0x3) << 8) | (l[index+1] if isinstance(l[index+1], int) else ord(l[index+1]))
                    cls._read_dns_name_from_index(l, offset, retlist)
                    index += 2
                    break
                if chunk_size == 0:
                    index += 1
                    break
                index += 1
                retlist.append(l[index: index + chunk_size])
                index += chunk_size
            return index
        except IndexError:
            raise Trunc("incomplete name")

    @classmethod
    def read_dns_name_from_index(cls, l, index):
        retlist = []
        next_index = cls._read_dns_name_from_index(l, index, retlist)
        return (next_index, ".".join([r.decode('utf-8') if isinstance(r, bytes) else r for r in retlist]))

    def next_rr(self, l, index, rr_list):
        array_len = len(l)
        if index > array_len:
            raise Trunc("next_rr: name truncated")
        index, name = self.read_dns_name_from_index(l, index)
        if index + 10 > array_len:
            raise Trunc("next_rr: truncated")
        qtype, qclass, ttl, rdlen = struct.unpack('!HHIH', l[index:index+10])
        if index + 10 + rdlen > array_len:
            raise Trunc("next_rr: data truncated")
        rddata = self.get_rddata(l, qtype, rdlen, index + 10)
        rr_list.append(dns.rr(name, qtype, qclass, ttl, rdlen, rddata))
        return index + 10 + rdlen

    def get_rddata(self, l, type, dlen, beg_index):
        if beg_index + dlen > len(l):
            raise Trunc('(dns) truncated rdata')
        if type == 1:
            if dlen != 4:
                raise Exception('(dns) invalid a data size', system='packet')
            return IPAddr(l[beg_index: beg_index + 4])
        elif type == 28:
            if dlen != 16:
                raise Exception('(dns) invalid a data size', system='packet')
            return IPAddr6.from_raw(l[beg_index: beg_index + dlen])
        elif type in (2, 5, 12):
            return self.read_dns_name_from_index(l, beg_index)[1]
        elif type == 15:
            return self.read_dns_name_from_index(l, beg_index + 2)[1]
        else:
            return l[beg_index: beg_index + dlen]

    def next_question(self, l, index):
        array_len = len(l)
        index, name = self.read_dns_name_from_index(l, index)
        if index + 4 > array_len:
            raise Trunc("next_question: truncated")
        qtype, qclass = struct.unpack('!HH', l[index:index+4])
        self.questions.append(dns.question(name, qtype, qclass))
        return index + 4

    class question(object):
        def __init__(self, name, qtype, qclass):
            self.name = name
            self.qtype = qtype
            self.qclass = qclass

        def __str__(self):
            s = self.name
            s += " " + rrtype_to_str.get(self.qtype, "#" + str(self.qtype))
            s += " " + rrclass_to_str.get(self.qclass, "#" + str(self.qclass))
            return s

    class rr(object):
        def __init__(self, _name, _qtype, _qclass, _ttl, _rdlen, _rddata):
            self.name = _name
            self.qtype = _qtype
            self.qclass = _qclass
            self.ttl = _ttl
            self.rdlen = _rdlen
            self.rddata = _rddata

        def __str__(self):
            s = self.name
            s += " " + rrtype_to_str.get(self.qtype, "#" + str(self.qtype))
            s += " " + rrclass_to_str.get(self.qclass, "#" + str(self.qclass))
            s += " ttl:" + str(self.ttl)
            s += " rdlen:" + str(self.rdlen)
            s += " datalen:" + str(len(self.rddata))
            if len(self.rddata) == 4:
                s += " data:" + str(IPAddr(self.rddata))
            return s
