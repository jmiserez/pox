
''' Crash the controller whenever any switch disconnects. Yay! '''

from pox.core import core
from pox.lib.revent import EventMixin
from pox.openflow import ConnectionUp, ConnectionDown

class buggy (EventMixin):
  ''' Crash the controller whenever any switch disconnects. Yay! '''
  def __init__ (self):
    core.openflow.addListener(ConnectionUp, self._handle_ConnectionUp)

  def _handle_ConnectionUp (self, event):
    event.connection.addListener(ConnectionDown, self._handle_ConnectionDown)

  def _handle_ConnectionDown (self, event):
    raise RuntimeError("You found the bug! Ten points to Gryffindor.")

def launch ():
  core.registerNew(buggy)
