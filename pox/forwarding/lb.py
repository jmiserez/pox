from pox.core import core
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.revent import EventContinue,EventHalt
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.openflow.discovery import Discovery
import sys
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST

log = core.getLogger()

############## Global constants #############

h1_ip = IPAddr("203.0.112.11")
h2_ip = IPAddr("203.0.112.12")
h1_mac = EthAddr("00:00:00:00:00:11")
h2_mac = EthAddr("00:00:00:00:00:12")

r1_ip = IPAddr("10.0.0.11")
r2_ip = IPAddr("10.0.0.12")
r1_mac = EthAddr("00:00:00:00:00:01")
r2_mac = EthAddr("00:00:00:00:00:02")

rtr_ip = IPAddr("203.0.112.1")
rtr_local = IPAddr("10.0.0.1")
rtr_mac = EthAddr("00:00:00:00:99:00")
rtr_mac2 = EthAddr("00:00:00:00:99:99")

virtual_ip = IPAddr("10.0.0.50")
virtual_mac = EthAddr("00:00:00:00:00:05")

server = {}
server[0] = {'ip':r1_ip, 'mac':r1_mac, 'outport': 2}
server[1] = {'ip':r2_ip, 'mac':r2_mac, 'outport': 2}
s1 = "00-00-00-00-00-01"
s2 = "00-00-00-00-00-02"
s3 = "00-00-00-00-00-03"
rtr = "00-00-00-00-00-04"
total_servers = len(server)

server_index = 0


arp_table = {
    r1_ip: r1_mac,
    r2_ip: r2_mac,
    h1_ip: h1_mac,
    h2_ip: h2_mac,
    virtual_ip: virtual_mac,
    rtr_ip: rtr_mac,
    rtr_local: rtr_mac2
}

################ Handlers ###################

class LoadBalancer(object):
    def __init__(self):
        global server
        global virtual_ip
        global virtual_mac
        global rtr
        self.servers = server
        self.virtual_ip = virtual_ip
        self.virtual_mac = virtual_mac
        core.openflow.addListeners(self)
        core.ARPHelper.addListeners(self)
        self.switches = {}
        self.rtr = rtr

    @property
    def total_servers(self):
        return len(self.servers)
    
    def _handle_ConnectionUp(self, event):
        log.info("Connection %s from switch %s" % (event.connection, dpidToStr(event.dpid)))
        self.switches[dpidToStr(event.dpid)] = event.connection
        if dpidToStr(event.dpid) == rtr:
            self.install_routes(event)

    def install_routes(self, event):
        log.debug("Intalling routes")
        # h1->h2
        msg = of.ofp_flow_mod()
        msg.in_port = 1
        msg.priority = 10
        msg.match = of.ofp_match(dl_src=h1_mac, dl_dst=h2_mac, in_port=1)
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        # h2->h1
        msg = of.ofp_flow_mod()
        msg.in_port = 2
        msg.priority = 10
        msg.match = of.ofp_match(dl_src=h2_mac, dl_dst=h1_mac, in_port=2)
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)
            
        # h*->s1
        msg = of.ofp_flow_mod()
        msg.in_port = 1
        msg.priority = 5
        msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=virtual_ip)
        msg.actions.append(of.ofp_action_dl_addr.set_dst(virtual_mac))
        msg.actions.append(of.ofp_action_output(port=3))
        event.connection.send(msg)

        # s1->h1
        msg = of.ofp_flow_mod()
        msg.in_port = 3
        msg.priority=5
        msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE,nw_src=virtual_ip, nw_dst=h1_ip)
        msg.actions.append(of.ofp_action_dl_addr.set_dst(h1_mac))
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)

        # s1->h2
        msg = of.ofp_flow_mod()
        msg.in_port = 3
        msg.priority = 5
        msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=virtual_ip, nw_dst=h2_ip)
        msg.actions.append(of.ofp_action_dl_addr.set_dst(h2_mac))
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)


    def arp_func(self, event):
        packet = event.parsed
        dpid = dpidToStr(event.dpid)
        log.debug("In arp code")
        a = packet.find('arp')
        if a:
            if a.opcode == arp.REQUEST:
                log.debug("Sending arp respond")
                if a.protodst == rtr_ip:
                    log.debug("Sending arp respond for rtr ip")
                    core.ARPHelper.send_arp_reply(event, a.hwsrc, src_mac=rtr_mac, src_ip = rtr_ip)
                elif a.protodst == rtr_local:
                    log.debug("Sending arp respond for rtr local")
                    core.ARPHelper.send_arp_reply(event, a.hwsrc, src_mac=rtr_mac2, src_ip = rtr_local)
                elif a.protodst in arp_table:
                    log.debug("Sending arp respond from %s %s to %s %s" % (a.protodst, arp_table[a.protodst], a.protosrc, a.hwsrc))
                    core.ARPHelper.send_arp_reply(event, a.hwsrc, src_mac=arp_table[a.protodst], src_ip = a.protodst)
                else:
                    log.info("No arp table entry for proto %s", a.protodst)


        else:
            log.info("Unknown packet at the router, %s" % packet)

    def to_r1(self, event):
        packet = event.parsed
        dpid = dpidToStr(event.dpid)
        index = 0
        selected_server_ip = self.servers[index]['ip']
        selected_server_mac = self.servers[index]['mac']

        # s1->rewrite(r1)->s2
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type=packet.type, dl_src=packet.src, dl_dst=packet.dst)
        if packet.type == ethernet.IP_TYPE:
            p = packet.next
            msg.match.nw_src = p.srcip
            msg.match.nw_dst = p.dstip
            
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, selected_server_mac))
        msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, selected_server_ip))
        msg.actions.append(of.ofp_action_output(port = 2))
        self.switches[s1].send(msg)
        
        # setup reverse route
        log.info("Reverse route on S1")
        reverse_msg = of.ofp_flow_mod()
        reverse_msg.in_port = 2
        reverse_msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, dl_src=selected_server_mac, nw_src=selected_server_ip,
                                         nw_dst=msg.match.nw_src)
        reverse_msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, virtual_mac))
        reverse_msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, virtual_ip))
        reverse_msg.actions.append(of.ofp_action_output(port = 1))
        self.switches[s1].send(reverse_msg)
            
        # s2->r1
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(dl_dst=r1_mac)
        msg2.actions.append(of.ofp_action_output(port=2))
        self.switches[s2].send(msg2)
        

        log.info("Reverse message on s2")
        reverse_msg2 = of.ofp_flow_mod()
        reverse_msg2.buffer_id = None
        reverse_msg2.in_port = 2
        reverse_msg2.match = of.ofp_match(dl_type=ethernet.IP_TYPE, dl_src=selected_server_mac, nw_src=selected_server_ip)
        
        reverse_msg2.actions.append(of.ofp_action_output(port = 1))
        self.switches[s2].send(reverse_msg2)

    def to_r2(self, event):
        packet = event.parsed
        dpid = dpidToStr(event.dpid)
        index = 1
        selected_server_ip = self.servers[index]['ip']
        selected_server_mac = self.servers[index]['mac']

        # s1->rewrite(r2)->s2
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type=packet.type, dl_src=packet.src, dl_dst=packet.dst)
        if packet.type == ethernet.IP_TYPE:
            p = packet.next
            msg.match.nw_src = p.srcip
            msg.match.nw_dst = p.dstip
            
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, selected_server_mac))
        msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, selected_server_ip))
        msg.actions.append(of.ofp_action_output(port = 3))
        self.switches[s1].send(msg)
        
        # setup reverse route
        log.info("Reverse route on S2")
        reverse_msg = of.ofp_flow_mod()
        reverse_msg.in_port = 3
        reverse_msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, dl_src=selected_server_mac, nw_src=selected_server_ip,
                                         nw_dst=msg.match.nw_src)
        reverse_msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, virtual_mac))
        reverse_msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, virtual_ip))
        reverse_msg.actions.append(of.ofp_action_output(port = 1))
        self.switches[s1].send(reverse_msg)
            
        # s3->r2
        msg2 = of.ofp_flow_mod()
        msg2.match = of.ofp_match(dl_dst=selected_server_mac)
        msg2.actions.append(of.ofp_action_output(port=2))
        self.switches[s3].send(msg2)
        

        log.info("Reverse message on s3")
        reverse_msg2 = of.ofp_flow_mod()
        reverse_msg2.buffer_id = None
        reverse_msg2.in_port = 2
        reverse_msg2.match = of.ofp_match(dl_type=ethernet.IP_TYPE, dl_src=selected_server_mac, nw_src=selected_server_ip)
        
        reverse_msg2.actions.append(of.ofp_action_output(port = 1))
        self.switches[s3].send(reverse_msg2)

            
    def _handle_PacketIn(self, event):
        packet = event.parsed
        dpid = dpidToStr(event.dpid)
        log.info("Handling packet in from switch %s on port %d src %s dst %s" % (dpidToStr(event.dpid), event.port, packet.src, packet.dst))

        # hanle arp request
        a = packet.find('arp')
        if a:
            self.arp_func(event)

        # Deal with the router separately
        if dpid == self.rtr:
            self.arp_func(event)
            return

        if not packet.type == ethernet.IP_TYPE:
            log.info("Cannot handle none IP packets")
            return

        if packet.dst == virtual_mac:
            log.info("Load balancing")
            log.info("Selecing r1")
            # FIXME: do round robin
            self.to_r2(event)

def launch ():
    import proto.arp_helper as arp_helper
    arp_helper.launch(eat_packets=False)
    
    log.info("Stateless LB running.")
    core.registerNew(LoadBalancer)

