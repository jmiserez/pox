from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.recoco.recoco import Timer
import time
from itertools import count
from functools import partial


log = core.getLogger()


XID = count(1000)


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


waiting_calls = {} #xid-> [list of function calls]


def get_barrier_msg():
  """
  Generate a barrier request message
  """
  barrier_msg = of.ofp_barrier_request()
  barrier_msg.xid = XID.next()
  log.info("Genrated barrier msg with xid: %d", barrier_msg.xid)
  return barrier_msg


class InternetSwitch(EventMixin):

  def __init__ (self, connection):
    self.connection = connection
    self.dpid = internet
    self.log = core.getLogger("InternalSwitch")
    self.log.debug("Initialized Internet Switch")
    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)

  def install_internal(self, priorty=1000):
    """Allow internal switches to talk to each others"""
    for src in internet_hosts:
      for dst in internet_hosts:
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_src=src, dl_dst=dst)
        msg.priority = priorty
        msg.actions.append(of.ofp_action_output(port=host_ports[dst]))
        self.connection.send(msg)

  def install_to_services(self, priorty=100):
    for host in internet_hosts:
      ip_msg = of.ofp_flow_mod()
      ip_msg.match = of.ofp_match(dl_type=0x0800, nw_dst=host_ips[host])
      ip_msg.priority = priorty
      ip_msg.actions.append(of.ofp_action_output(port=host_ports[host]))
      self.connection.send(ip_msg)

  def all_to_f2(self):
    out_priority = 100
    internet_msg = of.ofp_flow_mod()
    internet_msg.match = of.ofp_match()
    internet_msg.actions.append(of.ofp_action_output(port=4))
    internet_msg.priority = out_priority
    self.log.info("")
    self.connection.send(internet_msg)

  def install_v1(self):
    self.install_internal()
    # Just send everything else to F2
    self.install_to_services()
    self.all_to_f2()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    packet = event.parse()
    self.log.info("Ignoring packet in at Internet Switch: %s", str(packet))

  def _handle_BarrierIn(self, event):
    self.log.info("BARRIER REPLY: xid=%s", event.xid)
    if event.xid not in waiting_calls:
      self.log.warn("BARRIER REPLY for unkown xid=%s, current: %s", event.xid, waiting_calls.keys())
      return
    calls = waiting_calls[event.xid]
    del waiting_calls[event.xid]
    for call in calls:
      call()


class InternalSwitch(EventMixin):

  def __init__ (self, connection):
    self.connection = connection
    self.dpid = internal
    self.log = core.getLogger(self.__class__.__name__)
    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.traffic_map = {}
    """
    # Fill the internal traffic map
    for src in internal_hosts:
      for dst in internet_hosts:
        self.traffic_map[src] = host_ports[dst]
    """
    self.log.debug("Initialized Internal Switch")

  def install_internal(self, priority=1000):
    """Allow internal switches to talk to each others"""
    for host in internal_hosts:
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match(dl_dst=host)
      msg.priority = priority
      msg.actions.append(of.ofp_action_output(port=host_ports[host]))
      self.log.debug("Installing v1 rule: %s", str(msg).replace("\n", " "))
      self.connection.send(msg)

  def redirect_traffic(self, src, port, priority=100):
    self.traffic_map[src] = port
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_src=src)
    msg.actions.append(of.ofp_action_output(port=port))
    msg.priority = priority
    self.log.info("Redirect Traffic from src='%s' to port: %d" % (src, port))
    self.connection.send(msg)

  def remove_redirect_traffic(self, src):
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    msg.match = of.ofp_match(dl_type=0x0800, dl_src=src)
    self.log.info("Removing flow mod with dl_src='%s'", src)
    self.connection.send(msg)

  def tag_packet(self, src, dst, outport, vid, priority=1100):
    """
    Tag a packet from a Eth src to Eth dst with vlan value
    """
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type=0x0800, dl_src=src, dl_dst=dst)
    msg.actions.append(of.ofp_action_vlan_vid(vlan_vid=vid))
    msg.actions.append(of.ofp_action_output(port=outport))
    msg.priority = priority
    self.log.info("Tagging packets with VLAN='0x%x', src='%s', and dst='%s", vid, str(src), str(dst))
    self.connection.send(msg)

  def install_v1(self):
    self.log.info("Installing v1")
    self.install_internal()
    self.redirect_traffic(faculty, internal_ports[f3])
    self.redirect_traffic(student, internal_ports[f2])
    self.redirect_traffic(guest, internal_ports[f1])
    self.redirect_traffic(unknown, internal_ports[f1])

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    self.log.info("Ignoring packet in at Internal Switch: %s", str(packet))

  def _handle_BarrierIn(self, event):
    self.log.info("BARRIER REPLY: xid=%s", event.xid)
    if event.xid not in waiting_calls:
      self.log.warn("BARRIER REPLY for unkown xid=%s, current: %s", event.xid, waiting_calls.keys())
      return
    calls = waiting_calls[event.xid]
    del waiting_calls[event.xid]
    for call in calls:
      call()


class FSwitch(EventMixin):
  def __init__ (self, connection, dpid, deny=False):
    self.connection = connection
    self.deny = deny
    self.dpid = dpid
    self.traffic_map = {}
    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)

  def redirect_serivce(self, ip, port, priority=1000):
    self.traffic_map[ip] = port
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type=0x0800, nw_dst=ip)
    msg.actions.append(of.ofp_action_output(port=port))
    msg.priority = priority
    self.log.info("Redirect Service to src='%s' to port: %d" % (ip, port))
    self.connection.send(msg)

  def deny_service(self, ip, priority=1000):
    self.log.info("Denying Service to src='%s'", ip)
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type=0x0800, nw_dst=ip)
    msg.priority = priority
    self.log.info("Denying Service to src='%s'" % (ip,))
    self.connection.send(msg)

  def remove_redirect_service(self, ip):
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    msg.match = of.ofp_match(dl_type=0x0800, nw_dst=ip)
    self.log.info("Removing flow mod with nw_dst='%s'", ip)
    self.connection.send(msg)

  def monitor_service(self, ip):
    """
    Helper method to switch between denying a service and just redirecting it
    to the monitoring switch
    """
    if self.deny:
      self.deny_service(ip)
    else:
      self.redirect_serivce(ip, fs_ports[monitor])

  def allow_all(self, priority=100):
    """
    If packet incoming from internal network then output it to the Internet
    and vice versa.
    """
    # To internet Rules
    internet_msg = of.ofp_flow_mod()
    internet_msg.match = of.ofp_match(in_port=fs_ports[internal])
    internet_msg.actions.append(of.ofp_action_output(port=fs_ports[internet]))
    internet_msg.priority = priority

    # To internal Rules
    internal_msg = of.ofp_flow_mod()
    internal_msg.match = of.ofp_match(in_port=fs_ports[internet])
    internal_msg.actions.append(of.ofp_action_output(port=fs_ports[internal]))
    internal_msg.priority = priority

    self.connection.send(internal_msg)
    self.connection.send(internet_msg)

  def tag_packet(self, nw_src, nw_dst, output_port, vid, priority=1100):
    """
    Tag a packet from a Eth src to Eth dst with vlan ID
    """
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type=0x0800, nw_src=nw_src, nw_dst=nw_dst)
    msg.actions.append(of.ofp_action_vlan_vid(vlan_vid=vid))
    msg.actions.append(of.ofp_action_output(port=output_port))
    msg.priority = priority
    self.log.info("Tagging packets with VLAN='0x%x'", vid)
    self.log.info("Tagging packets with VLAN='0x%x', src='%s', and dst=%s", vid, str(nw_src), str(nw_dst))
    self.connection.send(msg)

  def untag_packet(self, nw_src, nw_dst, output_port, vid, priority=1100):
    """
    Remove tag from packet and output to a switch in fs_ports
    """
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type=0x0800, nw_dst=nw_dst)
    msg.actions.append(of.ofp_action_strip_vlan())
    msg.actions.append(of.ofp_action_output(port=output_port))
    msg.priority = priority
    self.log.info("Untagging packets with VLAN='0x%x' and dst=%s", vid, str(nw_dst))
    self.connection.send(msg)

  def _handle_BarrierIn(self, event):
    self.log.info("BARRIER REPLY: xid=%s", event.xid)
    if event.xid not in waiting_calls:
      self.log.warn("BARRIER REPLY for unkown xid=%s, current: %s", event.xid, waiting_calls.keys())
      return
    calls = waiting_calls[event.xid]
    del waiting_calls[event.xid]
    for call in calls:
      call()


class F1Switch(FSwitch):
  def __init__ (self, connection, deny=False):
    super(F1Switch, self).__init__(connection, f1, deny)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initialized F1 Switch")

  def install_v1(self):
    self.log.info("Installing v1")
    # Service1 Rules
    self.monitor_service(host_ips[service1])
    self.allow_all()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    packet = event.parse()
    log.info("XXX Ignoring packet in at F1 Switch: %s", str(packet))


class F2Switch(FSwitch):
  def __init__ (self, connection, deny=False):
    super(F2Switch, self).__init__(connection, f2, deny)
    self.log = core.getLogger(self.__class__.__name__)
    self.log.debug("Initialized F2 Switch")

  def install_v1(self):
    self.log.info("Installing v2")
    self.allow_all()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    packet = event.parse()
    log.info("XXX Ignoring packet in at F2 Switch: %s", str(packet))


class F3Switch(FSwitch):
  def __init__ (self, connection, deny=False):
    super(F3Switch, self).__init__(connection, f3, deny)
    self.log = core.getLogger("F3Switch")
    self.log.info("Initialized F3 Switch")

  def install_v1(self):
    self.log.info("Installing v1")
    self.allow_all()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    packet = event.parse()
    self.log.info("XXX Ignoring packet in at F3 Switch: %s", str(packet))


class MonitorSwitch(EventMixin):
  def __init__ (self, connection):
    self.connection = connection
    self.dpid = monitor
    self.log = core.getLogger(self.__class__.__name__)
    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)
    self.log.debug("Initialized MonitorSwitch Switch")

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

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """
    packet = event.parse()
    self.log.info("XXX Ignoring packet in at MonitorSwitch Switch: %s and port %d", str(packet) , event.port)

  def _handle_BarrierIn(self, event):
    self.log.info("BARRIER REPLY: xid=%s", event.xid)
    if event.xid not in waiting_calls:
      self.log.warn("BARRIER REPLY for unkown xid=%s, current: %s", event.xid, waiting_calls.keys())
      return
    calls = waiting_calls[event.xid]
    del waiting_calls[event.xid]
    for call in calls:
      call()


class Main(EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, consistent=True, update_wait=5, update_once=True,
                consistent_wait=5, deny=False, use_barriers=True,
                in_flight_wait=5, slow_update_wait=5):
    self.log = core.getLogger("Main")
    self.handlers = {}
    self.consistent = consistent
    self.update_wait = update_wait
    self.update_once = update_once
    self.consistent_wait = consistent_wait
    self.deny = deny
    self.use_barriers = use_barriers
    self.in_flight_wait = in_flight_wait
    self.slow_update_wait = slow_update_wait
    self._all_connected = False
    self.last_version = 0
    self.listenTo(core.openflow)

  def slow_update_sleep(self, fn, *args, **kwargs):
    self.log.info("Sleeping for '%d' secs to simulate slow update",
                  self.slow_update_wait)
    def wrapper(*ags, **kw):
      self.log.info("Woke up from simulating slow update.")
      fn(*ags, **kw)

    Timer(self.slow_update_wait, wrapper, *args, kw=kwargs, recurring=False)

  def consistent_update_sleep(self, fn, *args, **kwargs):
    self.log.info("Sleeping for '%d' secs to make sure writes are committed",
                  self.consistent_wait)
    def wrapper(*ags, **kw):
      self.log.info("Woke up from waiting for writes to committed.")
      fn(*ags, **kw)

    Timer(self.consistent_wait, wrapper, args=args, kw=kwargs, recurring=False)

  def in_flight_sleep(self, fn, *args, **kwargs):
    self.log.info("Sleeping for '%d' secs to make sure packets existed the link",
                  self.in_flight_wait)
    def wrapper(*ags, **kw):
      self.log.info("Woke up from waiting for in flight packets.")
      fn(*ags, **kw)

    Timer(self.in_flight_wait, wrapper, args=args, kw=kwargs, recurring=False)

  def v2_incosnsitent_update_barriers(self):
    self.log.info("XXX V2 Inconsistent Update with barriers")
    # Prepare the update requests and the barriers
    redir_guest_to_f2 = lambda: self.handlers[internal].redirect_traffic(guest, internal_ports[f2])
    barr1 = get_barrier_msg()
    req_barr1 = lambda: self.handlers[internal].connection.send(barr1)

    redir_student_to_f3 = lambda: self.handlers[internal].redirect_traffic(student, internal_ports[f3])
    barr2 = get_barrier_msg()
    req_barr2 = lambda: self.handlers[internal].connection.send(barr2)

    monitor_on_f2 = lambda: self.handlers[f2].monitor_service(host_ips[service1])
    barr3 = get_barrier_msg()
    req_barr3 = lambda: self.handlers[f2].connection.send(barr3)

    # Prepare the update sequence
    waiting_calls[barr1.xid] = [redir_student_to_f3, req_barr2]
    waiting_calls[barr2.xid] = [partial(self.slow_update_sleep, monitor_on_f2),
                                partial(self.slow_update_sleep, req_barr3)]
    waiting_calls[barr3.xid] = [lambda: self.log.info("Update to V2 is completed!")]

    # Start the update process
    redir_guest_to_f2()
    req_barr1()

  def v2_inconsistent_update_wait(self):
    self.log.info("XXX Inconsistent Update")
    # 1- Redirect guest to F2
    self.handlers[internal].redirect_traffic(guest, internal_ports[f2])
    # 2- Redirect students to F3
    self.handlers[internal].redirect_traffic(student, internal_ports[f3])
    # 3- Monitor traffic to service1 on F2
    monitor = lambda: self.handlers[f2].monitor_service(host_ips[service1])
    self.slow_update_sleep(monitor)

  def v2_consistent_update_barriers(self):
    self.log.info("XXX Consistent Update with barriers")
    # Prepare the update requests and the barriers

    # From the paper
    # 1- Update I to forward S traffic to F3, while continuing to
    #    forward U and G traffic to F1 and F traffic to F3.
    redir_student_to_f3 = lambda: self.handlers[internal].redirect_traffic(student, internal_ports[f3])
    barr1 = get_barrier_msg()
    req_barr1 = lambda: self.handlers[internal].connection.send(barr1)

    # 2- Wait until in-flight packets have been processed by F2.
    #wait_in_flight = lambda: self.slow_update_sleep()

    # 3- Update F2 to deny SSH packets.
    monitor_on_f2 = lambda: self.handlers[f2].monitor_service(host_ips[service1])
    barr2 = get_barrier_msg()
    req_barr2 = lambda: self.handlers[f2].connection.send(barr2)

    # 4- Update I to forward G traffic to F2, while continuing to
    #    forward U traffic to F1 and S and F traffic to F3.

    redir_guest_to_f2 = lambda: self.handlers[internal].redirect_traffic(guest, internal_ports[f2])
    barr3 = get_barrier_msg()
    req_barr3 = lambda: self.handlers[internal].connection.send(barr3)

    # Prepare the update sequence
    waiting_calls[barr1.xid] = [partial(self.in_flight_sleep, monitor_on_f2),
                                partial(self.in_flight_sleep, req_barr2)]
    waiting_calls[barr2.xid] = [redir_guest_to_f2, req_barr3]
    waiting_calls[barr3.xid] = [lambda : self.log.info("V2 update is completed!")]

    # Start the update process
    redir_student_to_f3()
    req_barr1()

  def v2_consistent_update_wait(self):
    self.log.info("XXX Consistent Update")
    # From the paper
    # 1- Update I to forward S traffic to F3, while continuing to
    #    forward U and G traffic to F1 and F traffic to F3.
    self.handlers[internal].redirect_traffic(student, internal_ports[f3])

    # 2- Wait until in-flight packets have been processed by F2.
    monitor = lambda: self.handlers[f2].monitor_service(host_ips[service1])
    redirect = lambda: self.handlers[internal].redirect_traffic(guest, internal_ports[f2])

    def monitor_then_redirect():
      monitor()
      self.slow_update_sleep(redirect)

    self.in_flight_sleep(monitor_then_redirect)

  def v3_consistent_update_barriers(self):
    self.log.info("XXX V3 Consistent Update with barriers")
    vlan = 0x111
    # Untagging at F1
    untag_unkown_on_f1 = \
      lambda: self.handlers[f1].untag_packet(nw_src=host_ips[unknown],
                                             nw_dst=host_ips[service1],
                                             output_port=fs_ports[monitor],
                                             vid=vlan)
    barr1 = get_barrier_msg()
    req_barr1 =lambda: self.handlers[f1].connection.send(barr1)

    # Untagging at F2
    untag_guest_on_f2 = \
      lambda: self.handlers[f2].untag_packet(nw_src=host_ips[guest],
                                             nw_dst=host_ips[service1],
                                             output_port=fs_ports[monitor],
                                             vid=vlan)
    barr2 = get_barrier_msg()
    req_barr2 =lambda: self.handlers[f2].connection.send(barr2)

    # Tagging Unknown -> Service1 on internal switch
    tag_unknown_on_i = \
      lambda: self.handlers[internal].tag_packet(src=unknown, dst=service1,
                                                 outport=internal_ports[f1],
                                                 vid=vlan)
    barr3 = get_barrier_msg()
    req_barr3 =lambda: self.handlers[internal].connection.send(barr3)

    # Tagging Guest -> Service1 on internal switch
    tag_guest_on_i = \
      lambda: self.handlers[internal].tag_packet(src=guest, dst=service1,
                                                 outport=internal_ports[f2],
                                                 vid=vlan)
    barr4 = get_barrier_msg()
    req_barr4 =lambda: self.handlers[internal].connection.send(barr4)

    # Remove pervious monitor rule from F1
    remove_monitor_f1 = \
      lambda: self.handlers[f1].remove_redirect_service(host_ips[service1])
    # Remove pervious monitor rule from F2
    remove_monitor_f2 = \
      lambda: self.handlers[f2].remove_redirect_service(host_ips[service1])

    remove_monitor_f1 = lambda: None
    remove_monitor_f2 = lambda: None

    waiting_calls[barr1.xid] = [tag_unknown_on_i, req_barr3]
    waiting_calls[barr2.xid] = [tag_guest_on_i, req_barr4]
    waiting_calls[barr3.xid] = [remove_monitor_f1]
    waiting_calls[barr4.xid] = [remove_monitor_f2]

    untag_unkown_on_f1()
    untag_guest_on_f2()

    def barriers():
      req_barr1()
      req_barr2()

    self.slow_update_sleep(barriers)

  def v3_inconsistent_update(self):
    self.log.info("XXX V3 Inconsistent Update with barriers")
    vlan = 0x111
    # Tagging Guest -> Service1 on internal switch
    self.handlers[internal].tag_packet(src=unknown, dst=service1, outport=internal_ports[f1], vid=vlan)

    # Tagging Unkown -> Service1 on internal switch
    self.handlers[internal].tag_packet(src=guest, dst=service1, outport=internal_ports[f2], vid=vlan)

    # Remove pervious monitor rule from F1
    self.handlers[f1].remove_redirect_service(host_ips[service1])
    # Remove pervious monitor rule from F2
    self.handlers[f2].remove_redirect_service(host_ips[service1])

    def after_time():
      # Untagging at F1
      self.handlers[f1].untag_packet(nw_src=host_ips[unknown], nw_dst=host_ips[service1], output_port=fs_ports[monitor], vid=vlan)

      # Untagging at F2
      self.handlers[f2].untag_packet(nw_src=host_ips[guest], nw_dst=host_ips[service1], output_port=fs_ports[monitor], vid=vlan)

    self.timer = Timer(self.consistent_sleep, after_time, recurring=False)

  def install_v2(self):
    self.log.info("Installing V2")
    if self.consistent:
      if self.use_barriers:
        self.v2_consistent_update_barriers()
      else:
        self.v2_consistent_update_wait()
    else:
      if self.use_barriers:
        self.v2_incosnsitent_update_barriers()
      else:
        self.v2_inconsistent_update_wait()

  def install_v3(self):
    self.log.info("XXX Consistent Update V3 with barriers")
    #untag_f2 = lambda : self.handlers[f2].untag_packet(guest, host_ips[service2])
    #untag_f2 = lambda : self.handlers[f2].untag_packet(guest, host_ips[service2])
    """
    self.handlers[f2].untag_packet(host_ips[guest], host_ips[service1], 100)
    self.handlers[f2].untag_packet(host_ips[unknown], host_ips[service1], 100)
    self.handlers[internal].tag_packet(guest, service1, 100)
    self.handlers[internal].tag_packet(unknown, service1, 100)
    """
    #self.v3_inconsistent_update()
    self.v3_consistent_update_barriers()

  def install_v4(self):
    pass

  def update_version(self):
    self.log.info("XXX Update version triggered, last version is '%d'", self.last_version)
    if self.last_version == 0:
      pass
      # TODO(AH): move installing v1 to here
    elif self.last_version == 1:
      self.install_v2()
      self.last_version = 2
    elif self.last_version == 2:
      self.install_v3()
      self.last_version = 3
    else:
      self.log.error("No version defined after version: %d", self.last_version)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s", event.connection)
    dpid = dpidToStr(event.dpid)
    if dpid == internal:
      sw = InternalSwitch(event.connection)
      sw.install_v1()
      self.handlers[internal] = sw
    elif dpid == f1:
      sw = F1Switch(event.connection, deny=self.deny)
      sw.install_v1()
      self.handlers[f1] = sw
    elif dpid == f2:
      sw = F2Switch(event.connection, deny=self.deny)
      sw.install_v1()
      self.handlers[f2] = sw
    elif dpid == f3:
      sw = F3Switch(event.connection, deny=self.deny)
      sw.install_v1()
      self.handlers[f3] = sw
    elif dpid == internet:
      sw = InternetSwitch(event.connection)
      sw.install_v1()
      self.handlers[internet] = sw
    elif dpid == monitor:
      sw = MonitorSwitch(event.connection)
      sw.install_v1()
      self.handlers[monitor] = sw
    else:
      log.error("Unkown switch with dpid %s", dpid)

    self.last_version = 1
    # Wait for all switches to get connected before starting the update timer
    connected = set(list(self.handlers.iterkeys()))
    all = set([internal, f1, f2, f3, internet, monitor])
    if connected == all:
      self._all_connected = True
      self.timer = Timer(self.update_wait, self.update_version,
                         recurring=not self.update_once)



def launch (consistent=True, update_wait=5, update_once=True,
            consistent_wait=5, deny=False, barriers=True, in_flight_wait=5,
            slow_update_wait=5):
  """
  Starts an L2 learning switch.

  :param consistent: If True a consistent update will be used
  :param update_wait: The amount of time before triggering version update
  :param update_once: If True only one update will be performed
  :param consistent_wait: How time to sleep to ensure consistency in algorithms
                           rely on timer to make sure the writes are committed.
  :param deny: If true filtered packets will be denied. Otherwise it will be
               sent to the monitoring switch.
  :param barriers: If true barriers will be used to make sure the writes are
                   comitted. Otherwise wait is used.
  :param in_flight_wait: the amount of time to wait for in flight packets
                         between two switches.
  :param slow_update_wait: time to wait before issuing the next flowMod to
                          simulate slow controller.
  """

  core.registerNew(Main, consistent=str_to_bool(consistent),
                   update_wait=int(update_wait),
                   update_once=str_to_bool(update_once),
                   consistent_wait=int(consistent_wait),
                   deny=str_to_bool(deny),
                   use_barriers=str_to_bool(barriers),
                   in_flight_wait=int(in_flight_wait),
                   slow_update_wait=int(slow_update_wait))
