
''' Whenever we a token from the server telling us to drop, drop! '''

from pox.core import core
from pox.lib.revent import EventMixin
from pox.openflow import ConnectionUp, ConnectionDown, PacketIn
import pox.openflow.libopenflow_01 as of
import pox.lib.packet.ethernet as ethernet
import pox.lib.packet.ipv4 as ipv4
from pox.lib.addresses import EthAddr

class fake_capability_manager(EventMixin):
  ''' Crash the controller whenever any switch disconnects. Yay! '''
  def __init__ (self):
    core.openflow.addListener(ConnectionUp, self._handle_ConnectionUp)
    self.connection = None

  def _handle_ConnectionUp (self, event):
    self.connection = event.connection
    event.connection.addListener(PacketIn, self._handle_PacketIn)

  def _handle_PacketIn(self, event):
     pkt = ethernet(raw=event.ofp.data)
     # Our "capability" is an TCP RST. Fake for now
     if (pkt.type == ethernet.IP_TYPE and
         pkt.next.protocol == ipv4.TCP_PROTOCOL and
         # pkt.next.next.RST and
         pkt.src == EthAddr("12:34:56:78:01:02")):
       msg = of.ofp_flow_mod()
       msg.priority = 123 # magic number
       msg.buffer_id = event.ofp.buffer_id
       #msg.actions = drop
       self.connection.send(msg)

def launch ():
  core.registerNew(fake_capability_manager)
