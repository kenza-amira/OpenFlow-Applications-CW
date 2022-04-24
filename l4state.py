from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.ether_types import ETH_TYPE_IP

class L4State14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4State14, self).__init__(*args, **kwargs)
        self.ht = set()

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
        #
        # write your code here
        #
        # tcph = pkt.get_protocols(tcp.tcp)
        # iph = pkt.get_protocols(ipv4.ipv4)
        # if len(tcph) != 0 and len(iph)!=0:
        #     iph = iph[0]
        #     if in_port == 1:
        #         if tcph[0].has_flags(tcp.TCP_SYN, tcp.TCP_RST) or tcph[0].has_flags(tcp.TCP_SYN, tcp.TCP_FIN) or tcph[0].has_flags(0):
        #             acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
        #         elif (iph.src, iph.dst, in_port, 2) not in self.ht:
        #             self.ht.add((iph.src, iph.dst, in_port, 2))
        #             acts = [psr.OFPActionOutput(2)]
        #             match = psr.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst, 
        #                                 ipv4_src=iph.src, ipv4_dst=iph.dst, tcp_src=tcph[0].src_port, 
        #                                 tcp_dst=tcph[0].dst_port)
        #             self.add_flow(dp, 1, match, acts, msg.buffer_id)
        #             if msg.buffer_id != ofp.OFP_NO_BUFFER:
        #                 return
        
        #     elif in_port == 2:
        #         if (iph.dst, iph.src, 1, in_port) in self.ht:
        #             acts = [psr.OFPActionOutput(1)]
        #             match = psr.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst, 
        #                                 ipv4_src=iph.src, ipv4_dst=iph.dst, tcp_src=tcph[0].src_port, 
        #                                 tcp_dst=tcph[0].dst_port)
        #             self.add_flow(dp, 1, match, acts, msg.buffer_id)
        #             if msg.buffer_id != ofp.OFP_NO_BUFFER:
        #                 return
        #         else:
        #             acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]  
        # else:
        #     out_port = 1 if in_port == 2 else 2
        #     acts = [psr.OFPActionOutput(out_port)]
        #  
        iph = pkt.get_protocols(ipv4.ipv4)
        tcph = pkt.get_protocols(tcp.tcp)
        out_port = 2 if in_port == 1 else 1
        acts = [psr.OFPActionOutput(out_port)]
        if not(len(tcph) == 0 or len(iph) == 0):
            if in_port == 1:
                flags = tcph[0].has_flags(tcp.TCP_SYN) or tcph[0].has_flags(tcp.TCP_RST) or tcph[0].has_flags(tcp.TCP_FIN) or tcph[0].has_flags(tcp.TCP_PSH) or tcph[0].has_flags(tcp.TCP_ACK) or tcph[0].has_flags(tcp.TCP_URG) or tcph[0].has_flags(tcp.TCP_ECE) or tcph[0].has_flags(tcp.TCP_CWR)
                if tcph[0].has_flags(tcp.TCP_FIN, tcp.TCP_SYN) or tcph[0].has_flags(tcp.TCP_RST, tcp.TCP_SYN) or not flags:
                    acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
                elif (iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port) not in self.ht:
                    self.ht.add((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port))
                    mtc = psr.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP, ipv4_src=iph[0].src, ipv4_dst=iph[0].dst, ip_proto=in_proto.IPPROTO_TCP, tcp_src=tcph[0].src_port, tcp_dst=tcph[0].dst_port)
                    acts = [psr.OFPActionOutput(out_port)]
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return
            elif in_port == 2:
                if (iph[0].dst, iph[0].src, tcph[0].dst_port, tcph[0].src_port) not in self.ht:
                    acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
                else:
                    mtc = psr.OFPMatch(in_port=in_port, eth_type=ETH_TYPE_IP, ipv4_src=iph[0].src, ipv4_dst=iph[0].dst, ip_proto=in_proto.IPPROTO_TCP, tcp_src=tcph[0].src_port, tcp_dst=tcph[0].dst_port)
                    acts = [psr.OFPActionOutput(out_port)]
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
