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
import time

log = core.getLogger()

vip = IPAddr("198.51.100.1")
h1 = IPAddr("123.123.1.3")
replica1 = IPAddr("123.123.2.3")
replica2 = IPAddr("123.123.3.3")
s1 = "00-00-00-00-00-01"
s2 = "00-00-00-00-00-02"
s3 = "00-00-00-00-00-03"

def encode_msg(msg):
  import base64
  if hasattr(msg, 'pack'):
    msg = msg.pack()
  return base64.b64encode(msg).replace("\n", "")

def print_msgin(dpid,msg):
  print "pox.forwarding.lb.HappensBefore-MessageIn-[{0}:{1}]".format(dpid, msg)
def print_msgout(dpid1,msg1,dpid2,msg2):
  print "pox.forwarding.lb.HappensBefore-MessageOut-[{0}:{1}:{2}:{3}]".format(dpid1, msg1, dpid2, msg2)


class LoadBalancer(object):
  """

  physical topology
                     h1-- 3-s1-2 --2-s2-3--replica1
                            1        1
                             \     /
                              \   /
                               2 1
                               s3-3---replica2

                           link used  
                           by install_replica1 when on s1,
                           and install_replica2 when on s2
                           
                           Race can happen
                           if rules are 
                           installed:
                           on s1: install_replica1
                           then on s2: install_replica2
                           then on s1: install_replica1
                           --------->
                           <---------
                           --------->
                           etc. 
                                                           
                     h1--s1 ------- s2--replica1
                           \        /
   link used by install_    \    < > link never used
   replica2 when on s1       \  /
       (case OK)              s3--replica2
    
  """
  def __init__(self):
    self.switches = {}
    core.openflow.addListeners(self)
    self.last = "replica1"
    self.delay = 1 # in seconds
    
    self.in_dpid = None
    self.in_msg = None
    
  def _send_out(self, dpid, msg):
    if self.in_dpid is not None and self.in_msg is not None:
      print_msgout(self.in_dpid, self.in_msg, dpid, encode_msg(msg))
    self.switches[dpid].send(msg)
    
  def _read_in(self, dpid, msg):
    self.in_dpid = dpid
    self.in_msg = encode_msg(msg)
    print_msgin(dpid, self.in_msg)

  def _handle_ConnectionUp(self, event):
    log.info("Connection %s from switch %s" % (event.connection, dpidToStr(event.dpid)))
    self.switches[dpidToStr(event.dpid)] = event.connection
    log.info("Switches connected %s" % self.switches.keys())

  def _handle_PacketIn(self, event):

    def install_replica1():
      if dpid == s1:
        log.info("on s1 installing s1->s2")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=vip)
        msg.match.tp_src = None
        msg.match.tp_dst = None
        #msg.actions.append(of.ofp_action_nw_addr.set_dst(replica1))
        msg.actions.append(of.ofp_action_output(port=2))
        self._send_out(s1,msg)

        log.info("on s1 PacketOut on s1->s2")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 2))
        self._send_out(s1,msg)

        time.sleep(self.delay)
 
        log.info("on s1 installing s2->replica1")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=vip)
        #msg2.match.nw_dst = replica1
        msg2.actions.append(of.ofp_action_output(port=3))
        self._send_out(s2,msg2)

      elif dpid == s2:
        log.info("on s2 installing s2->s1")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=vip)
        #msg2.match.nw_dst = replica1
        msg2.actions.append(of.ofp_action_output(port=of.OFPAT_OUTPUT))
        self._send_out(s2,msg2)

        log.info("on 2 PacketOut on s2->s1")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port=of.OFPAT_OUTPUT))
        self._send_out(s2,msg)

      elif dpid == s3:
        log.info("on s3 s3->replica2")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=vip)
        #msg2.match.nw_dst = replica1
        msg2.actions.append(of.ofp_action_output(port=3))
        self._send_out(s3,msg2)

        log.info("on s3 PacketOut on s3->r2")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 3))
        self._send_out(s3,msg)

      else:
          log.info("install_replica1: Unknown dpid %s %s" % (dpid, type(dpid)))

    def install_replica2():
      if dpid == s1:
        log.info("s1->rewrite(replica2)->s3")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.match.tp_src = None
        msg.match.tp_dst = None
        msg.actions.append(of.ofp_action_nw_addr.set_dst(replica2))
        msg.areplica2ions.append(of.ofp_action_output(port=1))
        self._send_out(s1,msg)

        log.info("PacketOut on s1")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 1))
        self._send_out(s1,msg)
        
        time.sleep(self.delay)
 
        log.info("s3->replica2")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(in_port=2)
        #msg2.match.nw_dst = replica1
        msg2.actions.append(of.ofp_action_output(port=3))
        self._send_out(s3,msg2)

#     elif dpid == s2:
        #
        # TODO what should we do here?
        
      elif dpid == s3:
        log.info("s3->replica1")
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(in_port=2)
        #msg2.match.nw_dst = replica1
        msg2.actions.append(of.ofp_action_output(port=3))
        self._send_out(s3,msg2)

        log.info("PacketOut on s3")
        msg = of.ofp_packet_out(in_port = event.port, data = packet.pack(),
                                action = of.ofp_action_output(port = 3))
        self._send_out(s3,msg)

      else:
          log.info("install_replica2: Unknown dpid %s %s" % (dpid, type(dpid)))

    dpid = dpidToStr(event.dpid)
    ofp_msg = event.ofp.pack()
    self._read_in(dpid, ofp_msg)
    packet = event.parsed

    
    log.info("Handling packet in from switch %s on port %d src %s dst %s" % (dpid, event.port, packet.src, packet.dst))
    # Packets coming from the outside

    if packet.type == ethernet.IP_TYPE:
      p = packet.next
      if p.dstip == vip:
        # Always choose replica1 as the first choice
        install_replica1()
        """
        if self.last == "replica1":
          install_replica2()
          self.last = "replica2"
        else:
          install_replica1()
          self.last = "replica1"
        """
      else:
        log.info("Packet not dest to server %s", p.dstip)
    else:
      log.info("Unknown packet type")

    log.info("DONE")


def launch ():
  core.registerNew(LoadBalancer)
  log.info("LB running.")
