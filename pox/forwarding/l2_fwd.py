from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.recoco.recoco import Timer
import time


log = core.getLogger()


h1 = EthAddr("12:34:56:78:01:02")
h2 = EthAddr("12:34:56:78:02:02")

hosts = [h1, h2]

s1 = "00-00-00-00-00-01"
s2 = "00-00-00-00-00-02"


hosts_map = {}
hosts_map[s1] = {}
hosts_map[s1][h1] = 2
hosts_map[s1][h2] = 1
hosts_map[s2] = {}
hosts_map[s2][h1] = 1
hosts_map[s2][h2] = 2


class S1(EventMixin):
  def __init__ (self, connection, consistent=False):
    self.s1_conn = connection
    self.s2_conn = None
    self.consistent = consistent

    self.listenTo(connection)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initializing %s", self.__class__.__name__)

  def get_dst_h1(self, event):
    packet = event.parse()
    s1_msg = of.ofp_flow_mod()
    #s1_msg.match = of.ofp_match.from_packet(packet)
    s1_msg.match = of.ofp_match(dl_dst=h1)
    s1_msg.actions.append(of.ofp_action_output(port=hosts_map[s1][h1]))
    s1_msg.buffer_id = event.ofp.buffer_id
    return s1_msg

  def get_dst_h2(self, event):
    packet = event.parse()
    s1_msg = of.ofp_flow_mod()
    #s1_msg.match = of.ofp_match.from_packet(packet)
    s1_msg.match = of.ofp_match(dl_dst=h2)
    s1_msg.actions.append(of.ofp_action_output(port=hosts_map[s1][h2]))
    s1_msg.buffer_id = event.ofp.buffer_id

    s2_msg = of.ofp_flow_mod()
    #s2_msg.match = of.ofp_match.from_packet(packet)
    s2_msg.match = of.ofp_match(dl_dst=h2)
    s2_msg.actions.append(of.ofp_action_output(port=hosts_map[s2][h2]))
    return s1_msg, s2_msg

  def inconsistent_PacketIn(self, event):
    """
    Inconsistent PacketIn handler update the first switch and push the packet
    back to the network before updating the second switch. So we will have
    another PacketIn from the other switch.
    """
    packet = event.parse()
    src = packet.src
    dst = packet.dst
    self.log.info("XXX Inconsistent Packet in %s->%s, in_port: %d", src, dst, event.port)
    if dst not in hosts:
      self.log.warn("XXXX Unkown dst in %s->%s, in_port: %d", src, dst, event.port)
      return
    if dst == h2:
      # I'm the first switch in the path
      s1_msg, s2_msg = self.get_dst_h2(event)

      self.s1_conn.send(s1_msg)
      self.log.info("XXX (2 hops) Installed  s1 %s->%s out on: %d", src, dst, hosts_map[s1][dst])
      self.s2_conn.send(s2_msg)
      self.log.info("XXX (2 hops) Installed  s2 %s->%s out on: %d", src, dst, hosts_map[s2][dst])
    elif dst == h1:
      # I'm the last switch in the path
      s1_msg = self.get_dst_h1(event)
      self.log.info("XXX (1 hop) Installed  s1 %s->%s out on: %d", src, dst, hosts_map[s1][dst])
      self.s1_conn.send(s1_msg)

  def consistent_PacketIn(self, event):
    packet = event.parse()
    src = packet.src
    dst = packet.dst
    self.log.info("XXX Consistent Packet in %s->%s, in_port: %d", src, dst, event.port)
    if dst not in hosts:
      self.log.warn("XXXX Unkown dst in %s->%s, in_port: %d", src, dst, event.port)
      return
    if dst == h2:
      # I'm the first switch in the path
      s1_msg, s2_msg = self.get_dst_h2(event)

      self.s2_conn.send(s2_msg)
      self.log.info("XXX (2 hops) Installed  s2 %s->%s out on: %d", src, dst, hosts_map[s2][dst])
      time.sleep(0.5)
      self.s1_conn.send(s1_msg)
      self.log.info("XXX (2 hops) Installed  s1 %s->%s out on: %d", src, dst, hosts_map[s1][dst])
    elif dst == h1:
      # I'm the last switch in the path
      s1_msg = self.get_dst_h1(event)
      self.log.info("XXX (1 hop) Installed  s1 %s->%s out on: %d", src, dst, hosts_map[s1][dst])
      self.s1_conn.send(s1_msg)

  def _handle_PacketIn (self, event):
    if self.consistent:
      self.consistent_PacketIn(event)
    else:
      self.inconsistent_PacketIn(event)



class S2(EventMixin):
  def __init__ (self, connection, consistent=False):
    self.s1_conn = None
    self.s2_conn = connection
    self.consistent = consistent

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initializing %s", self.__class__.__name__)

  def get_dst_h1(self, event):
    packet = event.parse()
    s1_msg = of.ofp_flow_mod()
    #s1_msg.match = of.ofp_match.from_packet(packet)
    s1_msg.match = of.ofp_match(dl_dst=h1)
    s1_msg.actions.append(of.ofp_action_output(port=hosts_map[s1][h1]))

    s2_msg = of.ofp_flow_mod()
    #s2_msg.match = of.ofp_match.from_packet(packet)
    s2_msg.match = of.ofp_match(dl_dst=h1)
    s2_msg.actions.append(of.ofp_action_output(port=hosts_map[s2][h1]))
    s2_msg.buffer_id = event.ofp.buffer_id
    return s1_msg, s2_msg

  def get_dst_h2(self, event):
    packet = event.parse()
    s2_msg = of.ofp_flow_mod()
    #s2_msg.match = of.ofp_match.from_packet(packet)
    s2_msg.match = of.ofp_match(dl_dst=h2)
    s2_msg.actions.append(of.ofp_action_output(port=hosts_map[s2][h2]))
    s2_msg.buffer_id = event.ofp.buffer_id
    return s2_msg

  def inconsistent_PacketIn(self, event):
    packet = event.parse()
    src = packet.src
    dst = packet.dst
    self.log.info("XXX Inconsistent Packet in %s->%s, in_port: %d", src, dst, event.port)
    if dst not in hosts:
      self.log.warn("XXXX Unkown dst in %s->%s, in_port: %d", src, dst, event.port)
      return
    if dst == h1:
      # I'm the first switch in the path
      s1_msg, s2_msg = self.get_dst_h1(event)

      self.s2_conn.send(s2_msg)
      self.log.info("XXX (2 hops) Installed  s1 %s->%s out on: %d", src, dst, hosts_map[s1][dst])
      time.sleep(0.1)
      self.s1_conn.send(s1_msg)
      self.log.info("XXX (2 hops) Installed  s2 %s->%s out on: %d", src, dst, hosts_map[s2][dst])
    elif dst == h2:
      # I'm the last switch in the path
      s2_msg = self.get_dst_h2(event)
      self.s2_conn.send(s2_msg)
      self.log.info("XXX (1 hops) Installed  s2 %s->%s out on: %d", src, dst, hosts_map[s2][dst])

  def consistent_PacketIn(self, event):
    packet = event.parse()
    src = packet.src
    dst = packet.dst
    self.log.info("XXX Consistent Packet in %s->%s, in_port: %d", src, dst, event.port)
    if dst not in hosts:
      self.log.warn("XXXX Unkown dst in %s->%s, in_port: %d", src, dst, event.port)
      return
    if dst == h1:
      # I'm the first switch in the path
      s1_msg, s2_msg = self.get_dst_h1(event)

      self.s1_conn.send(s1_msg)
      self.log.info("XXX (2 hops) Installed  s2 %s->%s out on: %d", src, dst, hosts_map[s2][dst])
      time.sleep(0.1)
      self.s2_conn.send(s2_msg)
      self.log.info("XXX (2 hops) Installed  s1 %s->%s out on: %d", src, dst, hosts_map[s1][dst])

    elif dst == h2:
      # I'm the last switch in the path
      s2_msg = self.get_dst_h2(event)
      self.s2_conn.send(s2_msg)
      self.log.info("XXX (1 hops) Installed  s2 %s->%s out on: %d", src, dst, hosts_map[s2][dst])

  def _handle_PacketIn (self, event):
    if self.consistent:
      self.consistent_PacketIn(event)
    else:
      self.inconsistent_PacketIn(event)


class Main(EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, consistent=False):
    self.listenTo(core.openflow)
    self.log = core.getLogger("Main")
    self.handlers = {}
    self.consistent = consistent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s", event.connection)
    dpid = dpidToStr(event.dpid)
    if dpid == s1:
      self.handlers[s1] = S1(event.connection, self.consistent)
    elif dpid == s2:
      self.handlers[s2] = S2(event.connection, self.consistent)

    if s1 in self.handlers and s2 in self.handlers:
      self.handlers[s1].s2_conn = self.handlers[s2].s2_conn
      self.handlers[s2].s1_conn = self.handlers[s1].s1_conn


def launch(consistent=False):
  core.registerNew(Main, consistent=str_to_bool(consistent))
