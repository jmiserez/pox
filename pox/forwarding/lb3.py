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
Run STS with command 'dpp2 1 "198.51.100.1"'
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

# def encode_msg(msg):
#   import base64
#   if hasattr(msg, 'pack'):
#     msg = msg.pack()
#   return base64.b64encode(msg).replace("\n", "")
# 
# def print_msgin(dpid,msg):
#   print "pox.forwarding.lb.HappensBefore-MessageIn-[{0}:{1}]".format(dpid, msg)
# def print_msgout(dpid1,msg1,dpid2,msg2):
#   print "pox.forwarding.lb.HappensBefore-MessageOut-[{0}:{1}:{2}:{3}]".format(dpid1, msg1, dpid2, msg2)


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
     
    self.next_replica = 1

  def forward_packet (self, packet, packet_in, out_port, dpid):
#     time.sleep(1)
    msg = of.ofp_packet_out()
    msg.in_port = packet_in.in_port
    if packet_in.in_port == out_port:
      new_out_port = of.OFPP_IN_PORT
      print "Sending back out the OFPP_IN_PORT"
    else:
      new_out_port = out_port
    
#     if packet_in.buffer_id != -1 and packet_in.buffer_id is not None:
#       msg.buffer_id = packet_in.buffer_id
#     else:
#       if packet.pack() is None:
#         return # no data
#       msg.data = packet.pack() # add raw packet data if not in buffer

#     msg.data = packet.pack()
    msg.buffer_id = packet_in.buffer_id
    action = of.ofp_action_output(port = new_out_port)
    msg.actions.append(action)
    self.switches[dpid].send(msg)
    
  def install_rule(self, packet, out_port, dpid):
    msg = of.ofp_flow_mod()
#     msg.match = of.ofp_match.from_packet(packet)
#     msg.match = of.ofp_match(nw_dst = vip)
    msg.match = of.ofp_match(nw_dst=vip)
    msg.match.tp_src = None
    msg.match.tp_dst = None
    msg.priority = 10
    msg.actions.append(of.ofp_action_output(port=out_port))
    self.switches[dpid].send(msg)
    # additional case for sending packets back out the in port
    msg2 = of.ofp_flow_mod()
#     msg.match = of.ofp_match.from_packet(packet)
#     msg.match = of.ofp_match(nw_dst = vip)
    msg2.match = of.ofp_match(nw_dst=vip)
    msg2.match.tp_src = None
    msg2.match.tp_dst = None
    msg2.match.in_port = out_port
    msg2.priority = 11 # higher priority
    msg2.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    self.switches[dpid].send(msg2)
        
  def _handle_ConnectionUp(self, event):
    log.info("Connection %s from switch %s" % (event.connection, dpidToStr(event.dpid)))
    self.switches[dpidToStr(event.dpid)] = event.connection
    log.info("Switches connected %s" % self.switches.keys())

  def _handle_PacketIn(self, event):

    def install_replica1(packet, dpid, packet_in):
      log.info("install_replica1: Currently on dpid %s" % dpid)
      
      if dpid == s1:
#         log.info("Need to install route s1 -> s2, s2 -> replica1, and push packet out port 2 towards s2 (replica1)")
        
        self.install_rule(packet, 2, s1)
        log.info("Installed s1 -> s2")
        self.install_rule(packet, 3, s2)
        log.info("Installed s2 -> replica1")
        
        self.forward_packet(packet, packet_in, 2, dpid)
        log.info("Sent packet from s1 -> s2")

      elif dpid == s2:
        self.install_rule(packet, 3, s2)
        log.info("Installed s2 -> replica1")
        
        self.forward_packet(packet, packet_in, 3, dpid)
        log.info("Sent packet from s2 -> replica1")

      elif dpid == s3:
        self.install_rule(packet, 2, s3)
        log.info("Installed s3 -> s1")
        self.install_rule(packet, 2, s1)
        log.info("Installed s1 -> s2")
        self.install_rule(packet, 3, s2)
        log.info("Installed s2 -> replica1")
        
        self.forward_packet(packet, packet_in, 2, dpid)
        log.info("Sent packet from s3 -> s1")

      else:
          log.info("install_replica1: Unknown dpid %s", dpid)

    def install_replica2(packet, dpid, packet_in):
      log.info("install_replica2: Currently on dpid %s" % dpid)
      
      if dpid == s1:
#         log.info("Need to install route s1 -> s2, s2 -> replica1, and push packet out port 2 towards s2 (replica1)")
        
        self.install_rule(packet, 1, s1)
        log.info("Installed s1 -> s3")
        self.install_rule(packet, 3, s3)
        log.info("Installed s3 -> replica2")
        
        self.forward_packet(packet, packet_in, 1, dpid)
        log.info("Sent packet from s1 -> s3")

      elif dpid == s2:
        self.install_rule(packet, 2, s1)
        log.info("Installed s2 -> s1")
        self.install_rule(packet, 1, s1)
        log.info("Installed s1 -> s3")
        self.install_rule(packet, 3, s3)
        log.info("Installed s3 -> replica2")
        
        self.forward_packet(packet, packet_in, 2, dpid)
        log.info("Sent packet from s2 -> s1")

      elif dpid == s3:
        self.install_rule(packet, 3, s3)
        log.info("Installed s3 -> replica2")
        
        self.forward_packet(packet, packet_in, 3, dpid)
        log.info("Sent packet from s3 -> replica2")

      else:
          log.info("install_replica2: Unknown dpid %s", dpid)

    def send_one_hop(packet, packet_in, dpid, dst_ip):
      if dst_ip == "123.123.1.3":
        if dpid == s1:
          self.forward_packet(packet, packet_in, 3, dpid) #  h1
        elif dpid == s2:
          self.forward_packet(packet, packet_in, 2, dpid) # s1
        elif dpid == s3:
          self.forward_packet(packet, packet_in, 2, dpid) # s1
      elif dst_ip == "123.123.2.3":
        if dpid == s1:
          self.forward_packet(packet, packet_in, 2, dpid) # s2
        elif dpid == s2:
          self.forward_packet(packet, packet_in, 3, dpid) #  h2
        elif dpid == s3:
          self.forward_packet(packet, packet_in, 1, dpid) # s2
      elif dst_ip == "123.123.3.3":
        if dpid == s1:
          self.forward_packet(packet, packet_in, 1, dpid) # s3
        elif dpid == s2:
          self.forward_packet(packet, packet_in, 1, dpid) # s3
        elif dpid == s3:
          self.forward_packet(packet, packet_in, 3, dpid) #  h3

    dpid = dpidToStr(event.dpid)
    
    packet_in = event.ofp # The actual ofp_packet_in message.
    
    packet = event.parsed
    src_mac = packet.src
    dst_mac = packet.dst
    if packet.type == ethernet.IP_TYPE:
      ipv4_packet = event.parsed.find("ipv4")
      # Do more processing of the IPv4 packet
      src_ip = ipv4_packet.srcip
      dst_ip = ipv4_packet.dstip

      if dst_ip == vip:
        """
        Use round robin logic
        """
        if self.next_replica == 1:
          install_replica1(packet, dpid, packet_in)
          log.info("Installed replica 1")
          self.next_replica = 2
        elif self.next_replica == 2:
          # For verifying the scenario we don't actually need to install the 2nd 
          #             replica. In fact, this breaks the scenario sometimes.
          # TODO(jm): Find a way to add this without breaking everything.
          #install_replica2(packet, dpid, packet_in)
          #log.info("Installed replica 2")
          log.info("Pass")
          self.next_replica = 1
      else:
        log.info("Packet not headed for VIP address, but to %s", dst_ip)
#         send_one_hop(packet, packet_in, dpid, dst_ip)
    else:
      log.info("Unknown packet type")
    log.info("Packet-In handled on %s.", str(dpid))


def launch ():
  core.registerNew(LoadBalancer)
  log.info("LB running.")
