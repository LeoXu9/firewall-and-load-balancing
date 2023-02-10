from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.tcp import TCP_SYN
from ryu.lib.packet.tcp import TCP_FIN
from ryu.lib.packet.tcp import TCP_RST
from ryu.lib.packet.tcp import TCP_ACK
from ryu.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP

class L4Lb(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4Lb, self).__init__(*args, **kwargs)
        self.ht = {} # {(<sip><vip><sport><dport>): out_port, ...}
        self.vip = '10.0.0.10'
        self.dips = ('10.0.0.2', '10.0.0.3')
        self.dmacs = ('00:00:00:00:00:02', '00:00:00:00:00:03')
        self.dmacs1 = '00:00:00:00:00:01'
        self.counter = 0
        #
        # write your code here, if needed
        #

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        return out

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        #######################
        # write your code here, if needed

        arp_ = eth.ethertype
        if arp_ == ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocols(arp.arp)
            arp_pkt = arp_pkt[0]
            if  arp_pkt.dst_ip == self.vip:
                if  arp.ARP_REQUEST == arp_pkt.opcode:
                    (reply, src, src_ip) = (arp.ARP_REPLY, eth.src, arp_pkt.src_ip)
                    packet_=packet.Packet()
                    packet_.add_protocol(ethernet.ethernet(ethertype=arp_, dst=eth.src, src=self.dmacs1))
                    packet_.add_protocol(arp.arp(opcode=reply, src_mac=self.dmacs[0], src_ip=self.vip,dst_mac=src,dst_ip=src_ip))
                    dp.send_msg(self._send_packet(dp,in_port,packet_))
                    return
            elif arp_pkt.src_ip == self.dips[0] or arp_pkt.src_ip == self.dips[1] and arp_pkt.opcode == arp.ARP_REQUEST:
                (reply, src, src_ip) = (arp.ARP_REPLY, eth.src, arp_pkt.src_ip)
                packet_=packet.Packet()
                packet_.add_protocol(ethernet.ethernet(ethertype=arp_, dst=eth.src, src=self.dmacs1))
                packet_.add_protocol(arp.arp(opcode=reply, src_mac=self.dmacs1, src_ip='10.0.0.1',dst_mac=src,dst_ip=src_ip))
                dp.send_msg(self._send_packet(dp,in_port,packet_))
                return

        #######################
        iph = pkt.get_protocols(ipv4.ipv4)
        tcph = pkt.get_protocols(tcp.tcp)
        #######################
        # write your code here

        if len(iph) != 0 and len(tcph) != 0:
            iph = iph[0]
            tcph = tcph[0]
            if iph.dst == self.vip:
                (src_,dst,src_port,dst_port) = (iph.src, iph.dst, tcph.src_port, tcph.dst_port)
                if (src_,dst,src_port,dst_port) not in self.ht:
                    self.ht[(src_,dst,src_port,dst_port)] = self.counter % 2 + 2
                    self.counter += 1
                out_port = self.ht[(src_,dst,src_port,dst_port)]
                acts = [psr.OFPActionSetField(ipv4_dst=self.dips[out_port-2]),psr.OFPActionSetField(eth_dst=self.dmacs[out_port-2]),psr.OFPActionOutput(out_port)]
                match = psr.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP,ipv4_src=iph.src,ipv4_dst=self.dips[out_port-2],ip_proto=iph.proto,tcp_src=tcph.src_port, tcp_dst=tcph.dst_port)
                self.add_flow(dp,1,match,acts,msg.buffer_id)
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    return
            if iph.src == self.dips[0] or iph.src == self.dips[1]:
                acts = [psr.OFPActionSetField(ipv4_src=self.vip),psr.OFPActionSetField(eth_dst=self.dmacs1),psr.OFPActionOutput(1)]
                match = psr.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP,ipv4_src=iph.src,ipv4_dst=iph.dst,ip_proto=iph.proto,tcp_src=tcph.src_port, tcp_dst=tcph.dst_port)
                self.add_flow(dp,1,match,acts,msg.buffer_id)
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    return

        #######################
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
