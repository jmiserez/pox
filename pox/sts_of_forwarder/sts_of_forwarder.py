
"""
Simple component to forward openflow commands from STS to a single openflow
switch acting as a controller cross-bar.
"""

from pox.openflow.software_switch import OFConnection
from pox.messenger.messenger import *
from pox.core import core
from pox.lib.revent import *

import base64

log = core.getLogger()

class sts_of_forwarder(EventMixin):
  """
  Waits for a single switch to connect, and forwards openflow commands
  sent by STS down to the switch. The purpose of forwarding through POX
  is essentially just to leverage the OpenFlow handshake code in POX, rather
  than having to re-implement it in STS.
  """
  def __init__(self):
    self.conn = None
    self.pending_commands = []
    core.messenger.addListener(MessageReceived, self._handle_global_MessageReceived, weak=True)
    self.listenTo(core.openflow)

  def _handle_ConnectionUp(self, event):
    log.debug("Connection %s", event.connection)
    if self.conn is not None:
      log.warn("A second switch connected! %s", event.connection)
    self.conn = event.connection
    for msg in self.pending_commands:
      self.conn.send(msg)

  def _handle_global_MessageReceived (self, event, msg):
    if 'sts_connection' in msg:
      # It's for me!
      # First consume the message.
      event.con.read()
      # Now store the connection object.
      # Claiming the message channel causes (local) MessageReceived to be triggered
      # from here on after.
      event.claim()
      event.con.addListener(MessageReceived, self._handle_MessageReceived, weak=True)
      log.debug("- opened connection to STS")

  def _handle_MessageReceived(self, event, msg):
    # Message handler for an individiual connection.
    if event.con.isReadable():
      r = event.con.read()
      # Should be a base64 encoded openflow message.
      b64_decoded = base64.b64decode(r)
      (msg, packet_length) = OFConnection.parse_of_packet(b64_decoded)
      if self.conn is None:
        self.pending_commands.append(msg)
      else:
        self.conn.send(msg)
    else:
      log.debug("- conversation finished")

def launch():
  """
  Starts an STS OpenFlow forwarder.

  Typical invocation involves telling POX what port to listen to the switch on, and
  telling the messenger component what port to listen to STS on:

  $ ./pox.py openflow.of_01 --address=10.1.1.1 --port=6634 \
             messenger.messenger --tcp_address=10.1.1.1 --tcp_port=98765 \
             sts_of_forwarder.sts_of_forwarder
  """
  core.registerNew(sts_of_forwarder)
