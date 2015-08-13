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

#
# This demo expects a 3x2 GridTopology, producing a topology that looks like the one in the
# Google Docs file with the description. Note that hosts h2 through h5 are unused.
#

s1 = "00-00-00-00-00-01"
s2 = "00-00-00-00-00-02"
s3 = "00-00-00-00-00-03"
s4 = "00-00-00-00-00-04"
s5 = "00-00-00-00-00-05"
s6 = "00-00-00-00-00-06"
expected_switches = list()
expected_switches.append(s1)
expected_switches.append(s2)
expected_switches.append(s3)
expected_switches.append(s4)
expected_switches.append(s5)
expected_switches.append(s6)
h1 = IPAddr("123.123.1.8")
h6 = IPAddr("123.123.6.8")

p_left = 1
p_right = 2
p_top = 3
p_bottom = 4
p_diaglr = 5
p_diaglrinv = 6
p_host = 8

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


class TrafficEngineering(object):
  def __init__(self):
    self.switches = {}
    core.openflow.addListeners(self)       
     
    self.next_replica = 1

  def forward_packet (self, packet, packet_in, out_port, dpid):
    msg = of.ofp_packet_out()
    msg.in_port = packet_in.in_port
    if packet_in.in_port == out_port:
      new_out_port = of.OFPP_IN_PORT
      print "Sending back out the OFPP_IN_PORT"
    else:
      new_out_port = out_port
    msg.buffer_id = packet_in.buffer_id # assume packet was buffered and is not raw 
    action = of.ofp_action_output(port = new_out_port)
    msg.actions.append(action)
    self.switches[dpid].send(msg)
    
  def install_rule(self, dpid, out_port, priority, host_dst):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=host_dst)
    msg.priority = priority
    msg.actions.append(of.ofp_action_output(port=out_port))
    self.switches[dpid].send(msg)
    # additional case for sending packets back out the in port, as that only supported when explicitely defined
    msg2 = of.ofp_flow_mod()
    msg2.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=host_dst)
    msg2.match.in_port = out_port
    msg2.priority = priority+1 # higher priority needed to induce race condition
    msg2.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    self.switches[dpid].send(msg2)
    
  def clear_rule(self, dpid, host_dst):
    if dpidToStr(dpid) in self.switches:
      match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=host_dst)
      clear = of.ofp_flow_mod(match=of.ofp_match(),command=of.OFPFC_DELETE)
        
  def _handle_ConnectionUp(self, event):
    log.info("Connection %s from switch %s" % (event.connection, dpidToStr(event.dpid)))
    self.switches[dpidToStr(event.dpid)] = event.connection
    log.info("Switches connected %s" % self.switches.keys())
    if set(expected_switches).issubset(set(self.switches.keys())):
      # all switches connected
      log.info("All switches connected, installing GREEN path")
      self.install_path_green()
      self.install_returnpath_green()
  
  def install_path_green(self):
      log.info("install_path_green: h1-1-2-3-6-h6")
      prio = 10
      self.install_rule(s1, p_right, prio, host_dst=h6)
      self.install_rule(s2, p_right, prio, host_dst=h6)
      self.install_rule(s3, p_bottom, prio, host_dst=h6)
      self.install_rule(s6, p_host, prio, host_dst=h6)
      #return path (we'll keep this)
      self.install_rule(s1, p_host, prio, host_dst=h1)
      self.install_rule(s2, p_left, prio, host_dst=h1)
      self.install_rule(s3, p_left, prio, host_dst=h1)
      self.install_rule(s6, p_top, prio, host_dst=h1)
      
  def install_returnpath_green(self):
      log.info("install_path_green: h1-1-2-3-6-h6")
      prio = 10
      #return path (we'll keep this)
      self.install_rule(s1, p_host, prio, host_dst=h1)
      self.install_rule(s2, p_left, prio, host_dst=h1)
      self.install_rule(s3, p_left, prio, host_dst=h1)
      self.install_rule(s6, p_top, prio, host_dst=h1)
      
  def install_path_red(self):
      log.info("install_path_red: h1-1-4-5-2-6-h6")
      prio = 20
      self.install_rule(s1, p_bottom, prio, host_dst=h6)
      self.install_rule(s4, p_right, prio, host_dst=h6)
      self.install_rule(s5, p_top, prio, host_dst=h6)
      self.install_rule(s2, p_diaglr, prio, host_dst=h6)
      self.install_rule(s6, p_host, prio, host_dst=h6)
      
  def install_path_orange(self):
      log.info("install_path_orange: h1-1-2-5-6-h6")
      prio = 20
      self.install_rule(s1, p_right, prio, host_dst=h6)
      self.install_rule(s2, p_bottom, prio, host_dst=h6)
      self.install_rule(s5, p_right, prio, host_dst=h6)
      self.install_rule(s6, p_host, prio, host_dst=h6)
      
  def clear_path_green(self):
    self.clear_rule(s1, host_dst=h6)
    self.clear_rule(s2, host_dst=h6)
    self.clear_rule(s3, host_dst=h6)
    self.clear_rule(s6, host_dst=h6)
    
  def clear_path_red(self):
    self.clear_rule(s1, host_dst=h6)
    self.clear_rule(s4, host_dst=h6)
    self.clear_rule(s5, host_dst=h6)
    self.clear_rule(s2, host_dst=h6)
    self.clear_rule(s6, host_dst=h6)
    
  def clear_path_orange(self):
    self.clear_rule(s1, host_dst=h6)
    self.clear_rule(s2, host_dst=h6)
    self.clear_rule(s5, host_dst=h6)
    self.clear_rule(s6, host_dst=h6)

  def _handle_PacketIn(self, event):
    dpid = dpidToStr(event.dpid)
    packet_in = event.ofp # The actual ofp_packet_in message.
    log.info("Packet-In ignored on %s.", str(dpid))
    
  def _handle_ConnectionDown (self, event):
    dpid = dpidToStr(event.dpid)
    self.switches[dpidToStr(event.dpid)] = None
    if dpid == s3:
       log.info("Rerouting to RED/ORANGE (race) due to Connection-Down on %s.", str(dpid))
       self.clear_path_green()
       self.install_path_red()
       self.clear_path_red()
       self.install_path_orange()
    else:
      log.info("Connection-Down ignored on %s.", str(dpid))

def launch ():
  core.registerNew(TrafficEngineering)
  log.info("TE running.")
