# Copyright 2011
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
Implementation of an OpenFlow flow table

@author: Colin Scott (cs@cs.berkeley.edu)

"""
from collections import namedtuple
from libopenflow_01 import *
from pox.lib.revent import *

import time
import logging
import math

log = logging.getLogger("FlowTable")

class OFPFMFC_OVERLAP_Exception(Exception):
    pass

# FlowTable Entries:
#   match - ofp_match (13-tuple)
#   counters - hash from name -> count. May be stale
#   actions - ordered list of ofp_action_*s to apply for matching packets
class TableEntry (object):
  """
  Models a flow table entry, with a match, actions, and options/flags/counters.
  Note: the current time can either be specified explicitely with the optional 'now' parameter or is taken from time.time()
  """

  def __init__(self,priority=OFP_DEFAULT_PRIORITY, cookie = 0, idle_timeout=0, hard_timeout=0, flags=0, match=ofp_match(), actions=[], buffer_id=-1, now=None, **kw):
    # overriding __new__ instead of init to make fields optional. There's probably a better way to do this.
    if now==None: now = time.time()
    self.counters = {
        'created': now,
        'last_touched': now,
        'bytes': 0,
        'packets': 0
    }
    self.priority = kw.get('priority', priority)
    self.cookie = kw.get('cookie', cookie)
    self.idle_timeout = kw.get('idle_timeout', idle_timeout)
    self.hard_timeout = kw.get('hard_timeout', hard_timeout)
    self.flags = kw.get('flags', flags)
    self.match = kw.get('match', match)
    #print kw['match']
    self.actions = kw.get('actions', actions)
    self.buffer_id = kw.get('buffer_id', buffer_id)

  @staticmethod
  def from_flow_mod(flow_mod):
    priority = flow_mod.priority
    cookie = flow_mod.cookie
    match = flow_mod.match
    actions = flow_mod.actions
    buffer_id = flow_mod.buffer_id
    flags = flow_mod.flags

    return TableEntry(priority, cookie, flow_mod.idle_timeout, flow_mod.hard_timeout, flags, match, actions, buffer_id)

  def to_flow_mod(self, flags=None, **kw):
    if not flags:
      flags = self.flags
    return ofp_flow_mod(priority = self.priority, cookie = self.cookie,
            match = self.match, idle_timeout = self.idle_timeout,
            hard_timeout = self.hard_timeout, actions = self.actions,
            buffer_id = self.buffer_id, flags = flags, **kw)

  def is_matched_by(self, match, priority = None, strict = False, out_port=None):
    """ return whether /this/ entry is matched by some other entry (e.g., for FLOW_MOD updates) """
    check_port = lambda: out_port == None or any(isinstance(a, ofp_action_output) and a.port == out_port for a in self.actions)

    if(strict):
      return (self.match == match and self.priority == priority) and check_port()
    else:
      return match.matches_with_wildcards(self.match) and check_port()
    
  def check_overlap(self, match, priority = 0):
    if self.priority == priority:
      return self.match.check_overlap(match)
    else:
      return False

  def touch_packet(self, byte_count, now=None):
    """ update the counters and expiry timer of this entry for a packet with a given byte count"""
    if now==None: now = time.time()
    self.counters["bytes"] += byte_count
    self.counters["packets"] += 1
    self.counters["last_touched"] = now

  def is_expired_idle(self, now=None):
    """" return whether this flow entry is expired due to its idle timeout"""
    if now==None: now = time.time()
    return (self.idle_timeout > 0 and now - self.counters["last_touched"] > self.idle_timeout)
  
  def is_expired_hard(self, now=None):
    """" return whether this flow entry is expired due to its hard timeout"""
    if now==None: now = time.time()
    return (self.hard_timeout > 0 and now - self.counters["created"] > self.hard_timeout)

  def __str__ (self):
    return self.__class__.__name__ + "\n  " + self.show()

  def __repr__(self):
    return "TableEntry("+self.show() + ")"

  def show(self):
       return "priority=%s, cookie=%x, idle_timeoout=%d, hard_timeout=%d, match=%s, actions=%s buffer_id=%s" % (
          self.priority, self.cookie, self.idle_timeout, self.hard_timeout, self.match, repr(self.actions), str(self.buffer_id))
       
  def duration_sec_nsec(self, now=None):
    """
    Return the duration this flow has been installed.
    Returns a tuple of two ints with (seconds, nanoseconds). The total installed time in
    nanoseconds is duration_sec*10^9+duration_nsec
    """
    frac_sec,full_sec = math.modf(now - self.counters["created"])
    return (int(full_sec),int(frac_sec * 1e9))
  
  def duration_in_nanoseconds(self, now=None):
    duration_sec,duration_nsec = self.duration_sec_nsec(now)
    return duration_sec*10^9+duration_nsec

  def flow_stats(self, now=None):
    if now is None: now = time.time()
    dur_sec,dur_nsec = self.duration_sec_nsec(now)
    return ofp_flow_stats (
        match = self.match,
        duration_sec=dur_sec,
        duration_nsec=dur_nsec,
        priority = self.priority,
        idle_timeout = self.idle_timeout,
        hard_timeout = self.hard_timeout,
        cookie = self.cookie,
        packet_count = self.counters["packets"],
        byte_count = self.counters["bytes"],
        actions = self.actions
        )
    
  def flow_removed (self, reason, now=None):
    if now is None: now = time.time()
    dur_sec,dur_nsec = self.duration_sec_nsec(now)
    fr = ofp_flow_removed()
    fr.match = self.match
    fr.cookie = self.cookie
    fr.priority = self.priority
    fr.reason = reason
    fr.duration_sec = dur_sec
    fr.duration_nsec = dur_nsec
    fr.idle_timeout = self.idle_timeout
    fr.hard_timeout = self.hard_timeout
    fr.packet_count = self.counters["packets"]
    fr.byte_count = self.counters["bytes"]
    return fr

  def aggregate_stats (self, match, out_port=None):
    mc_es = self.matching_entries(match=match, strict=False, out_port=out_port)
    packet_count = 0
    byte_count = 0
    flow_count = 0
    for entry in mc_es:
      packet_count += entry.packet_count
      byte_count += entry.byte_count
      flow_count += 1
    return ofp_aggregate_stats(packet_count=packet_count,
                               byte_count=byte_count,
                               flow_count=flow_count)

class FlowTableModification (Event):
  def __init__(self, added=[], removed=[], modified=[], reason=None, now=None):
    Event.__init__(self)
    self.added = added
    self.removed = removed
    self.modified = modified
    self.reason = reason
    self.now = now

class FlowTable (EventMixin):
  _eventMixin_events = set([FlowTableModification])

  """
  General model of a flow table. Maintains an ordered list of flow entries, and finds
  matching entries for packets and other entries. Supports expiration of flows.
  """
  def __init__(self, **kw):
    EventMixin.__init__(self)
    # For now we represent the table as a multidimensional array.
    #
    # [ (cookie, match, counters, actions),
    #   (cookie, match, counters, actions),
    #    ...                        ]
    #
    # Implies O(N) lookup for now. TODO: fix
    self.table = kw.get('table', [])

  @property
  def entries(self):
    return self.table

  def __len__(self):
    return len(self.table)

  def add_entry(self, entry):
    if not isinstance(entry, TableEntry):
      raise "Not an Entry type"
    self.table.append(entry)

    # keep table sorted by descending priority, with exact matches always going first
    # note: python sort is stable
    self.table.sort(key=lambda(e): (e.priority if e.match.is_wildcarded else (1<<16) + 1), reverse=True)

    self.raiseEvent(FlowTableModification(added=[entry]))

  def remove_entries(self, entries=[], reason=None, now=None):
    for entry in entries:
      if not isinstance(entry, TableEntry):
        raise "Not an Entry type"
      self.table.remove(entry)
      self.raiseEvent(FlowTableModification(removed=[entry], reason=reason, now=now))
  
  def modify_entries(self, actions, entries=[]):
    for entry in entries:
      if not isinstance(entry, TableEntry):
        raise "Not an Entry type"
      entry.actions = actions
      self.raiseEvent(FlowTableModification(modified=[entry]))
                      
  def entries_for_port(self, port_no):
    entries = []
    for entry in self.table:
      actions = entry.actions
      if len(actions) > 0:
        last_action = actions[-1]
        if type(last_action) == ofp_action_output:
          outgoing_port = last_action.port#.port_no
          if outgoing_port == port_no:
            entries.append(entry)
    return entries

  def matching_entries(self, match, priority=0, strict=False, out_port=None):
    return [ entry for entry in self.table if entry.is_matched_by(match, priority, strict, out_port) ]

  def flow_stats(self, match, out_port=None, now=None):
    return ( e.flow_stats() for e in self.matching_entries(match=match, strict=False, out_port=out_port))

  def table_stats(self):
    return ofp_table_stats()

  def expired_entries_idle(self, now=None):
    return [ entry for entry in self.table if entry.is_expired_idle(now) ]
  
  def expired_entries_hard(self, now=None):
    return [ entry for entry in self.table if entry.is_expired_hard(now) ]

  def remove_expired_entries(self, now=None):
    if now==None: now = time.time()
    remove_flows_hard = self.expired_entries_hard(now)
    self.remove_entries(remove_flows_hard, reason=OFPRR_HARD_TIMEOUT, now=now)
    remove_flows_idle = self.expired_entries_idle(now)
    self.remove_entries(remove_flows_idle, reason=OFPRR_IDLE_TIMEOUT, now=now)
    removed_flows = remove_flows_hard + remove_flows_idle
    return removed_flows

  def remove_matching_entries(self, match, priority=0, strict=False, out_port=None, reason=None, now=None):
    if now==None: now = time.time()
    remove_flows = self.matching_entries(match, priority, strict, out_port)
    self.remove_entries(remove_flows, reason=reason, now=now)
    return remove_flows
  
  def modify_matching_entries(self, actions, match, priority=0, strict=False):
    modify_flows = self.matching_entries(match, priority, strict)
    self.modify_entries(actions, modify_flows)
    return modify_flows

  def entry_for_packet(self, packet, in_port):
    """ return the highest priority flow table entry that matches the given packet
    on the given in_port, or None if no matching entry is found. """
    packet_match = ofp_match.from_packet(packet, in_port)

    for entry in self.table:
      if entry.match.matches_with_wildcards(packet_match, consider_other_wildcards=False):
        return entry
    else:
      return None
  
  def overlapping_entries(self, match, priority = 0):
    return [ entry for entry in self.table if entry.check_overlap(match, priority) ]

class SwitchFlowTable(FlowTable):
  """
  Model a flow table for our switch implementation. Handles the behavior in response
  to the OF messages send to the switch
  """

  def process_flow_mod(self, flow_mod):
    """ Process a flow mod sent to the switch
    @return a tuple (added|modified|removed, [list of affected entries])
    """
    if flow_mod.command == OFPFC_ADD:
      if(flow_mod.flags & OFPFF_CHECK_OVERLAP):
        if len(self.overlapping_entries(flow_mod.match, flow_mod.priority)) > 0:
          raise OFPFMFC_OVERLAP_Exception()
      # exactly matching entries have to be removed, but strangely these should not trigger FLOW_REMOVED messages
      self.remove_matching_entries(flow_mod.match,flow_mod.priority, strict=True, reason=None)
      return ("added", self.add_entry(TableEntry.from_flow_mod(flow_mod)))
    elif flow_mod.command == OFPFC_MODIFY or flow_mod.command == OFPFC_MODIFY_STRICT:
      is_strict = (flow_mod.command == OFPFC_MODIFY_STRICT)
      modified = self.modify_matching_entries(flow_mod.actions, flow_mod.match, priority=flow_mod.priority, strict=is_strict)
      if(len(modified) == 0):
        # if no matching entry is found, modify acts as add
        return ("added", self.add_entry(TableEntry.from_flow_mod(flow_mod)))
      else:
        return ("modified", modified)

    elif flow_mod.command == OFPFC_DELETE or flow_mod.command == OFPFC_DELETE_STRICT:
      is_strict = (flow_mod.command == OFPFC_DELETE_STRICT)
      out_port = flow_mod.out_port
      return ("removed", self.remove_matching_entries(flow_mod.match, flow_mod.priority, is_strict, out_port=out_port, reason=OFPRR_DELETE))
    else:
      raise AttributeError("Command not yet implemented: %s" % flow_mod.command)

class NOMFlowTable(EventMixin):
  _eventMixin_events = set([FlowTableModification])
  """
  Model a flow table for use in our NOM model. Keep in sync with a switch through a
  connection.
  """
  ADD = OFPFC_ADD
  REMOVE = OFPFC_DELETE
  REMOVE_STRICT = OFPFC_DELETE_STRICT
  TIME_OUT = 2

  def __init__(self, switch=None, **kw):
    EventMixin.__init__(self)
    self.flow_table = kw.get('flow_table', FlowTable())
    self.switch = kw.get('switch', switch)

    # a list of pending flow table entries : tuples (ADD|REMOVE, entry)
    self._pending = []

    # a map of pending barriers barrier_xid-> ([entry1,entry2])
    self._pending_barrier_to_ops = {}
    # a map of pending barriers per request entry -> (barrier_xid, time)
    self._pending_op_to_barrier = {}

    self.listenTo(switch)

  def install(self, entries=[]):
    """ asynchronously install entries in the flow table. will raise a FlowTableModification event when
        the change has been processed by the switch """
    self._mod(entries, NOMFlowTable.ADD)

  def remove_with_wildcards(self, entries=[]):
    """ asynchronously remove entries in the flow table. will raise a FlowTableModification event when
        the change has been processed by the switch """
    self._mod(entries, NOMFlowTable.REMOVE)

  def remove_strict(self, entries=[]):
    """ asynchronously remove entries in the flow table. will raise a FlowTableModification event when
        the change has been processed by the switch """
    self._mod(entries, NOMFlowTable.REMOVE_STRICT)

  @property
  def entries(self):
    return self.flow_table.entries

  @property
  def num_pending(self):
    return len(self._pending)

  def __len__(self):
    return len(self.flow_table)

  def _mod(self, entries, command):
    if isinstance(entries, TableEntry):
      entries = [ entries ]

    for entry in entries:
      if(command == NOMFlowTable.REMOVE):
        self._pending = filter(lambda(command, pentry): not (command == NOMFlowTable.ADD and entry.matches_with_wildcards(pentry)), self._pending)
      elif(command == NOMFlowTable.REMOVE_STRICT):
        self._pending = filter(lambda(command, pentry): not (command == NOMFlowTable.ADD and entry == pentry), self._pending)

      self._pending.append( (command, entry) )

    self._sync_pending()

  def _sync_pending(self, clear=False):
    if not self.switch.connected:
      return False

    # resync the switch
    if clear:
      self._pending_barrier_to_ops = {}
      self._pending_op_to_barrier = {}
      self._pending = filter(lambda(op): op[0] == NOMFlowTable.ADD, self._pending)

      self.switch.send(ofp_flow_mod(command=OFPFC_DELETE, match=ofp_match()))
      self.switch.send(ofp_barrier_request())

      todo = map(lambda(e): (NOMFlowTable.ADD, e), self.flow_table.entries) + self._pending
    else:
      todo = [ op for op in self._pending
          if op not in self._pending_op_to_barrier or (self._pending_op_to_barrier[op][1] + NOMFlowTable.TIME_OUT) < time.time ]

    for op in todo:
      fmod_xid = self.switch._xid_generator.next()
      flow_mod = op[1].to_flow_mod(xid=fmod_xid, command=op[0], flags=op[1].flags | OFPFF_SEND_FLOW_REM)
      log.info("NOMFlowTable: _sync_pending: send flow_mod %s", flow_mod)

      self.switch.send(flow_mod)

    barrier_xid = self.switch._xid_generator.next()
    self.switch.send(ofp_barrier_request(xid=barrier_xid))
    now = time.time()
    self._pending_barrier_to_ops[barrier_xid] = todo

    for op in todo:
      self._pending_op_to_barrier[op] = (barrier_xid, now) #this hangs


  def _handle_SwitchConnectionUp(self, event):
    # sync all_flows
    self._sync_pending(clear=True)

  def _handle_SwitchConnectionDown(self, event):
    # connection down. too bad for our unconfirmed entries
    self._pending_barrier_to_ops = {}
    self._pending_op_to_barrier = {}

  def _handle_BarrierIn(self, barrier):
    # yeah. barrier in. time to sync some of these flows
    if barrier.xid in self._pending_barrier_to_ops:
      added = []
      removed = []
      #print "barrier in: pending for barrier: %d: %s" % (barrier.xid, self._pending_barrier_to_ops[barrier.xid])
      for op in self._pending_barrier_to_ops[barrier.xid]:
        (command, entry) = op
        if(command == NOMFlowTable.ADD):
          self.flow_table.add_entry(entry)
          added.append(entry)
        else:
          removed.extend(self.flow_table.remove_matching_entries(entry.match, entry.priority, strict=command == NOMFlowTable.REMOVE_STRICT))
        self._pending.remove(op)
      del self._pending_barrier_to_ops[barrier.xid]
      self.raiseEvent(FlowTableModification(added = added, removed=removed))
      return EventHalt
    else:
      return EventContinue

  def _handle_FlowRemoved(self, event):
    """ process a flow removed event -- remove the matching flow from the table. """
    flow_removed = event.ofp
    for entry in self.flow_table.entries:
      if(flow_removed.match == entry.match and flow_removed.priority == entry.priority):
        #print "Removing matching entry from NOM"
        self.flow_table.remove_entries(entries=[entry])
        self.raiseEvent(FlowTableModification(removed=[entry]))
        return EventHalt
    return EventContinue
