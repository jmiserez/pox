# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
Turns your complex OpenFlow switches into stupid hubs.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet

log = core.getLogger()

vip = IPAddr("198.51.100.1")
h1 = IPAddr("123.123.1.3")
r1 = IPAddr("123.123.2.3")
r2 = IPAddr("123.123.3.3")
s1 = "00-00-00-00-00-01"
s2 = "00-00-00-00-00-02"
s3 = "00-00-00-00-00-03"

class LoadBalancer(object):
  def __init__(self):
    self.switches = {}
    core.openflow.addListeners(self)
    self.last = "r1"


  def _handle_ConnectionUp(self, event):
    log.info("Connection %s from switch %s" % (event.connection, dpidToStr(event.dpid)))
    self.switches[dpidToStr(event.dpid)] = event.connection
    log.info("Switches connected %s" % self.switches.keys())

  def _handle_PacketIn(self, event):

    def install_r1():
      if dpid == s1:
        log.info("s1->rewrite(r1)->s2")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.match.tp_src = None
        msg.match.tp_dst = None
        msg.actions.append(of.ofp_action_nw_addr.set_dst(r1))
        msg.actions.append(of.ofp_action_output(port=2))
        self.switches[s1].send(msg)

        log.info("PacketOut on s1")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 2))
        self.switches[s1].send(msg)

        log.info("s2->r1")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(in_port=2)
        #msg2.match.nw_dst = r1
        msg2.actions.append(of.ofp_action_output(port=3))
        self.switches[s2].send(msg2)

      elif dpid == s2:
        log.info("s2->r1")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(in_port=2)
        #msg2.match.nw_dst = r1
        msg2.actions.append(of.ofp_action_output(port=3))
        self.switches[s2].send(msg2)

        log.info("PacketOut on s2")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 3))
        self.switches[s2].send(msg)
      else:
          log.info("Unkown dpid %s %s" % (dpid, type(dpid)))

    def install_r2():
      if dpid == s1:
        log.info("s1->rewrite(r2)->s3")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.match.tp_src = None
        msg.match.tp_dst = None
        msg.actions.append(of.ofp_action_nw_addr.set_dst(r2))
        msg.actions.append(of.ofp_action_output(port=1))
        self.switches[s1].send(msg)

        log.info("PacketOut on s1")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 1))
        self.switches[s1].send(msg)

        log.info("s3->r2")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(in_port=2)
        #msg2.match.nw_dst = r1
        msg2.actions.append(of.ofp_action_output(port=3))
        self.switches[s3].send(msg2)

      elif dpid == s3:
        log.info("s3->r1")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(in_port=2)
        #msg2.match.nw_dst = r1
        msg2.actions.append(of.ofp_action_output(port=3))
        self.switches[s3].send(msg2)

        log.info("PacketOut on s3")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 3))
        self.switches[s3].send(msg)
      else:
          log.info("Unkown dpid %s %s" % (dpid, type(dpid)))

    packet = event.parsed
    dpid = dpidToStr(event.dpid)
    log.info("Handling packet in from switch %s on port %d src %s dst %s" % (dpid, event.port, packet.src, packet.dst))
    # Packets coming from the outside

    if packet.type == ethernet.IP_TYPE:
      p = packet.next
      if p.dstip == vip:
        if self.last == "r1":
          install_r2()
          self.last = "r2"
        else:
          install_r1()
          self.last = "r1"
      else:
        log.info("Packet not dest to server %s", p.dstip)
    else:
      log.info("Unkown packet type")





    log.info("DONE")







def launch ():
  core.registerNew(LoadBalancer)
  log.info("LB running.")
