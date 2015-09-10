from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
import time

log = core.getLogger()


faculty = EthAddr("00:00:00:00:00:02")
student = EthAddr("00:00:00:00:00:03")
guest = EthAddr("00:00:00:00:00:04")
unknown = EthAddr("00:00:00:00:00:05")
service1 = EthAddr("00:00:00:00:00:06")
service2 = EthAddr("00:00:00:00:00:07")

internal_hosts = [faculty, student, guest, unknown]
internet_hosts = [service1, service2]


host_ips = {}
host_ips[faculty] = IPAddr("10.0.0.2")
host_ips[student] = IPAddr("10.0.0.3")
host_ips[guest] = IPAddr("10.0.0.4")
host_ips[unknown] = IPAddr("10.0.0.5")
host_ips[service1] = IPAddr("128.0.0.2")
host_ips[service2] = IPAddr("128.0.0.3")

host_ports = {}
host_ports[faculty] = 1
host_ports[student] = 2
host_ports[guest] = 3
host_ports[unknown] = 4
host_ports[service1] = 1
host_ports[service2] = 2

internal = "00-00-00-00-00-01"
f1 = "00-00-00-00-00-02"
f2 = "00-00-00-00-00-03"
f3 = "00-00-00-00-00-04"
monitor = "00-00-00-00-00-05"
internet = "00-00-00-00-00-06"


internal_ports = {}
internal_ports[faculty] = 1
internal_ports[student] = 2
internal_ports[guest] = 3
internal_ports[unknown] = 4
internal_ports[f1] = 5
internal_ports[f2] = 6
internal_ports[f3] = 7

# F1, F2, and F3 have identical port mapping
fs_ports = {}
fs_ports[internal] = 1
fs_ports[internet] = 2
fs_ports[monitor] = 3


class InternetSwitch(EventMixin):

  def __init__ (self, connection):
    self.connection = connection

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log = core.getLogger("InternalSwitch")
    self.log.debug("Initializing Internet Switch")

  def install_internal(self):
    """Allow internal switches to talk to each others"""
    for host in internet_hosts:
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match(dl_dst=host)
      #msg.idle_timeout = 300
      #msg.hard_timeout = 300
      msg.priority = 1000
      msg.actions.append(of.ofp_action_output(port=host_ports[host]))
      self.connection.send(msg)

  def install_v1(self):
    self.install_internal()
    # Just send everything else to F2
    out_priority = 100
    internet_msg = of.ofp_flow_mod()
    internet_msg.match = of.ofp_match()
    internet_msg.actions.append(of.ofp_action_output(port=4))
    internet_msg.priority = out_priority
    self.log.info("")
    self.connection.send(internet_msg)

  def install_v2(self):
    """No change"""
    self.install_v1()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    self.log.info("Ignoring packet in at Internet Switch: %s", str(packet))


class InternalSwitch(EventMixin):

  def __init__ (self, connection):
    self.connection = connection

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initializing Internal Switch")

  def install_internal(self):
    """Allow internal switches to talk to each others"""
    for host in internal_hosts:
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match(dl_dst=host)
      msg.priority = 1000
      msg.actions.append(of.ofp_action_output(port=host_ports[host]))
      self.log.debug("Installing v1 rule: %s", str(msg).replace("\n", " "))
      self.connection.send(msg)

  def install_v1(self):
    self.log.info("Installing v1")
    self.install_internal()
    out_priority = 100
    # Faculty Rules
    faculty_msg = of.ofp_flow_mod()
    faculty_msg.match = of.ofp_match(nw_src=host_ips[faculty])
    faculty_msg.actions.append(of.ofp_action_output(port=internal_ports[f3]))
    faculty_msg.priority = out_priority

    # Student Rules
    student_msg = of.ofp_flow_mod()
    student_msg.match = of.ofp_match(nw_src=host_ips[student])
    student_msg.actions.append(of.ofp_action_output(port=internal_ports[f2]))
    student_msg.priority = out_priority

    # Guest Rules
    guest_msg = of.ofp_flow_mod()
    guest_msg.match = of.ofp_match(nw_src=host_ips[guest])
    guest_msg.actions.append(of.ofp_action_output(port=internal_ports[f1]))
    guest_msg.priority = out_priority

    # Unkown Rules
    unkown_msg = of.ofp_flow_mod()
    unkown_msg.match = of.ofp_match(nw_src=host_ips[unknown])
    unkown_msg.actions.append(of.ofp_action_output(port=internal_ports[f1]))
    unkown_msg.priority = out_priority

    self.connection.send(faculty_msg)
    self.connection.send(student_msg)
    self.connection.send(guest_msg)
    self.connection.send(unkown_msg)

  def install_v2(self):
    self.log.info("Installing v2")
    self.install_internal()
    out_priority = 100
    # Faculty Rules
    faculty_msg = of.ofp_flow_mod()
    faculty_msg.match = of.ofp_match(nw_src=host_ips[faculty])
    faculty_msg.actions.append(of.ofp_action_output(port=internal_ports[f3]))
    faculty_msg.priority = out_priority

    # Student Rules
    student_msg = of.ofp_flow_mod()
    student_msg.match = of.ofp_match(nw_src=host_ips[student])
    student_msg.actions.append(of.ofp_action_output(port=internal_ports[f3]))
    student_msg.priority = out_priority

    # Guest Rules
    guest_msg = of.ofp_flow_mod()
    guest_msg.match = of.ofp_match(nw_src=host_ips[guest])
    guest_msg.actions.append(of.ofp_action_output(port=internal_ports[f2]))
    guest_msg.priority = out_priority

    # Unkown Rules
    unkown_msg = of.ofp_flow_mod()
    unkown_msg.match = of.ofp_match(nw_src=host_ips[unknown])
    unkown_msg.actions.append(of.ofp_action_output(port=internal_ports[f1]))
    unkown_msg.priority = out_priority

    self.connection.send(faculty_msg)
    self.connection.send(student_msg)
    self.connection.send(guest_msg)
    self.connection.send(unkown_msg)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    self.log.info("Ignoring packet in at Internal Switch: %s", str(packet))


class F1Switch(EventMixin):
  def __init__ (self, connection):
    self.connection = connection

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initializing F1 Switch")

  def install_v1(self):
    # Service1 Rules
    s1_msg = of.ofp_flow_mod()
    s1_msg.match = of.ofp_match(nw_src=host_ips[service1])
    s1_msg.actions.append(of.ofp_action_output(port=fs_ports[monitor]))
    s1_msg.priority = 1000

    # To internet Rules
    internet_msg = of.ofp_flow_mod()
    internet_msg.match = of.ofp_match(in_port=fs_ports[internal])
    internet_msg.actions.append(of.ofp_action_output(port=fs_ports[internet]))
    internet_msg.priority = 100

    # To internal Rules
    internal_msg = of.ofp_flow_mod()
    internal_msg.match = of.ofp_match(in_port=fs_ports[internet])
    internal_msg.actions.append(of.ofp_action_output(port=fs_ports[internal]))
    internal_msg.priority = 100

    self.connection.send(s1_msg)
    self.connection.send(internal_msg)
    self.connection.send(internet_msg)

  def install_v2(self):
    self.log.info("Installing v2")
    self.install_v1()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    log.info("XXX Ignoring packet in at F1 Switch: %s", str(packet))


class F2Switch(EventMixin):
  def __init__ (self, connection):
    self.connection = connection

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initializing F2 Switch")

  def install_v1(self):
    # To internet Rules
    internet_msg = of.ofp_flow_mod()
    internet_msg.match = of.ofp_match(in_port=fs_ports[internal])
    internet_msg.actions.append(of.ofp_action_output(port=fs_ports[internet]))
    internet_msg.priority = 100

    # To internal Rules
    internal_msg = of.ofp_flow_mod()
    internal_msg.match = of.ofp_match(in_port=fs_ports[internet])
    internal_msg.actions.append(of.ofp_action_output(port=fs_ports[internal]))
    internal_msg.priority = 100

    self.connection.send(internal_msg)
    self.connection.send(internet_msg)

  def install_v2(self):
    self.log.info("Installing v2")
    # Service1 Rules
    s1_msg = of.ofp_flow_mod()
    s1_msg.match = of.ofp_match(nw_src=host_ips[service1])
    s1_msg.actions.append(of.ofp_action_output(port=fs_ports[monitor]))
    s1_msg.priority = 1000

    # To internet Rules
    internet_msg = of.ofp_flow_mod()
    internet_msg.match = of.ofp_match(in_port=fs_ports[internal])
    internet_msg.actions.append(of.ofp_action_output(port=fs_ports[internet]))
    internet_msg.priority = 100

    # To internal Rules
    internal_msg = of.ofp_flow_mod()
    internal_msg.match = of.ofp_match(in_port=fs_ports[internet])
    internal_msg.actions.append(of.ofp_action_output(port=fs_ports[internal]))
    internal_msg.priority = 100

    self.connection.send(s1_msg)
    self.connection.send(internal_msg)
    self.connection.send(internet_msg)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    log.info("XXX Ignoring packet in at F2 Switch: %s", str(packet))


class F3Switch(EventMixin):
  def __init__ (self, connection):
    self.connection = connection

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log = core.getLogger("F3Switch")
    self.log.info("Initializing F3 Switch")

  def install_v1(self):
    self.log.info("Installing v1")
    # To internet Rules
    internet_msg = of.ofp_flow_mod()
    internet_msg.match = of.ofp_match(in_port=fs_ports[internal])
    internet_msg.actions.append(of.ofp_action_output(port=fs_ports[internet]))
    internet_msg.priority = 100

    # To internal Rules
    internal_msg = of.ofp_flow_mod()
    internal_msg.match = of.ofp_match(in_port=fs_ports[internet])
    internal_msg.actions.append(of.ofp_action_output(port=fs_ports[internal]))
    internal_msg.priority = 100

    self.connection.send(internal_msg)
    self.connection.send(internet_msg)

  def install_v2(self):
    self.log.info("Installing v2")
    self.install_v1()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    self.log.info("XXX Ignoring packet in at F3 Switch: %s", str(packet))


class MonitorSwitch(EventMixin):
  def __init__ (self, connection):
    self.connection = connection

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initializing MonitorSwitch Switch")

  def install_v1(self):
    self.log.info("installing v1")
    # from f1
    f1_msg = of.ofp_flow_mod()
    f1_msg.match = of.ofp_match(in_port=1)
    f1_msg.actions.append(of.ofp_action_output(port=4))

    # From f2
    f2_msg = of.ofp_flow_mod()
    f2_msg.match = of.ofp_match(in_port=2)
    f2_msg.actions.append(of.ofp_action_output(port=4))

    # From f3
    f3_msg = of.ofp_flow_mod()
    f3_msg.match = of.ofp_match(in_port=3)
    f3_msg.actions.append(of.ofp_action_output(port=4))

    self.connection.send(f1_msg)
    self.connection.send(f2_msg)
    self.connection.send(f3_msg)

  def install_v2(self):
    self.log.info("installing v2")
    self.install_v1()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    self.log.info("XXX Ignoring packet in at MonitorSwitch Switch: %s and port %d", str(packet) , event.port)


class Main(EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self):
    self.listenTo(core.openflow)
    self.handlers = {}
  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s", event.connection)
    dpid = dpidToStr(event.dpid)
    if dpid == internal:
      sw = InternalSwitch(event.connection)
      sw.install_v2()
      self.handlers[internal] = sw
    elif dpid == f1:
      sw = F1Switch(event.connection)
      sw.install_v2()
      self.handlers[f1] = sw
    elif dpid == f2:
      sw = F2Switch(event.connection)
      sw.install_v2()
      self.handlers[f2] = sw
    elif dpid == f3:
      sw = F3Switch(event.connection)
      sw.install_v2()
      self.handlers[f3] = sw
    elif dpid == internet:
      sw = InternetSwitch(event.connection)
      sw.install_v2()
      self.handlers[internet] = sw
    elif dpid == monitor:
      sw = MonitorSwitch(event.connection)
      sw.install_v2()
      self.handlers[monitor] = sw
    else:
      log.error("Unkown switch with dpid %s", dpid)


def launch ():
  """
  Starts an L2 learning switch.
  """
  core.registerNew(Main)

