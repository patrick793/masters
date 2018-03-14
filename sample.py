# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp, ipv4, tcp, udp
from ryu.lib.packet import ether_types, in_proto

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host, get_all_host

from ryu.lib import hub

# import time

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        self.client_cnt = 2
        self.server_cnt = 2

        self.mac_to_port = {}
        self.port_to_mac = {}
        self.mac_to_ip = {}

        self.get_topology_data_success = False

        # Virtual Load Balancer IP
        self.controller_ip = "10.0.0.100"

        # Virtual Load Balancer MAC Address
        self.controller_mac = "11:22:33:ab:cd:ef"

        self.total_hosts = 0
       
        self.server_ips = []
        for x in range(self.server_cnt):
            self.server_ips.append("10.0.0.%s" % (x+1))
            self.total_hosts += 1

        self.client_ips = []
        for x in range(self.client_cnt):
            self.total_hosts += 1
            self.client_ips.append("10.0.0.%s" % (self.total_hosts))

        self.datapaths = {}

        self.spine_dpids = []
        self.server_leaf_dpids = []
        self.client_leaf_dpids = []
        self.dpid_to_mac = {}

        self.is_init = True
        self.init_thread = hub.spawn(self.init_delay)

        # Test
        self.target_mac = "00:00:00:00:00:01"
        self.target_ip = "10.0.0.1"

        self.is_rr = True

        # For Round-robin
        self.cur_spine_index = 0        
        self.cur_server_leaf_index = 0

    def init_delay(self):
        hub.sleep(1)
        # time.sleep(5)

        self.is_init = False

        # Final Initializations
        for x,_ in self.datapaths.items():
            if x not in self.server_leaf_dpids and x not in self.client_leaf_dpids:
                self.spine_dpids.append(x)

        self.server_leaf_dpids.sort()
        self.client_leaf_dpids.sort()

        # Set meters for spine switches

        # for dpid in self.spine_dpids:
        #     datapath = self.datapaths[dpid]
        #     ofproto = datapath.ofproto
        #     parser = datapath.ofproto_parser

        #     bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=1000, burst_size=10)]
        #     req=parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=99, bands=bands)
        #     datapath.send_msg(req)

        self.logger.info("Initialization complete!")
        self.logger.info(self.mac_to_port)
        self.logger.info("spine_dpids: " + str(self.spine_dpids))
        self.logger.info("server_leaf_dpids: " + str(self.server_leaf_dpids))
        self.logger.info("client_leaf_dpids: " + str(self.client_leaf_dpids))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions, 0)

        self.datapaths[datapath.id] = datapath

        links_list = get_link(self, None)
        # links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        
        for link in links_list:
            self.mac_to_port.setdefault(link.src.dpid, {})
            self.port_to_mac.setdefault(link.src.dpid, {})
            self.mac_to_port[link.src.dpid][link.dst.dpid] = link.src.port_no
            self.port_to_mac[link.src.dpid][link.src.port_no] = link.dst.dpid

        self.logger.info("Successful getting topology data!")

        for x in self.server_ips:
            self.send_arp(datapath, x)
        for x in self.client_ips:
            self.send_arp(datapath, x)

    def send_arp(self, datapath, dst_ip, dst_mac=None, out_port=None, opcode=arp.ARP_REQUEST):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if out_port == None:
            out_port = datapath.ofproto.OFPP_FLOOD
        if dst_mac == None:
            dst_mac = 'ff:ff:ff:ff:ff:ff'

        pkt = packet.Packet()
        e = ethernet.ethernet(
            dst_mac,
            self.controller_mac,
            ether_types.ETH_TYPE_ARP)
        r = arp.arp(
            opcode=opcode,
            src_mac=self.controller_mac,
            src_ip=self.controller_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(r)
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data)
        datapath.send_msg(out)


    def add_flow(self, datapath, match, actions, priority=ofproto_v1_3.OFP_DEFAULT_PRIORITY, idle_timeout=0, buffer_id=None, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        if meter_id != 0:
            inst.append(parser.OFPInstructionMeter(meter_id,ofproto.OFPIT_METER))

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, cookie=cookie)
        datapath.send_msg(mod)

    def arp_init(self, datapath, arp_header, in_port):
        dpid = datapath.id

        if arp_header.dst_ip == self.controller_ip and arp_header.opcode == arp.ARP_REPLY:
            # print(arp_header)
            if arp_header.src_ip in self.server_ips:
                self.server_leaf_dpids.append(dpid)
                self.dpid_to_mac[dpid] = arp_header.src_mac
                self.mac_to_ip[arp_header.src_mac] = arp_header.src_ip
            elif arp_header.src_ip in self.client_ips:
                self.client_leaf_dpids.append(dpid)
                self.dpid_to_mac[dpid] = arp_header.src_mac
                self.mac_to_ip[arp_header.src_mac] = arp_header.src_ip

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.port_to_mac.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port, eth.ethertype)

        # learn a mac address to avoid FLOOD next time.
        if src != self.controller_mac:
            self.mac_to_port[dpid][src] = in_port
            self.port_to_mac[dpid][in_port] = src

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # print("It's ARP")           
            arp_header = pkt.get_protocols(arp.arp)[0]
            if self.is_init == True:
                self.arp_init(datapath, arp_header, in_port)
                return
            if arp_header.dst_ip == self.controller_ip and arp_header.opcode == arp.ARP_REQUEST:
                self.send_arp(datapath, arp_header.src_ip, arp_header.src_mac, in_port, arp.ARP_REPLY)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_header = pkt.get_protocols(ipv4.ipv4)[0]

            # print(str(dpid) + " " + str(ip_header.proto))

            if ip_header.dst == self.controller_ip and ip_header.proto == in_proto.IPPROTO_TCP:
                tcp_header = pkt.get_protocols(tcp.tcp)[0]
                
                cur_spine_dpid = self.spine_dpids[self.cur_spine_index]
                cur_server_leaf_dpid = self.server_leaf_dpids[self.cur_server_leaf_index]
                cur_target_server_mac =  self.dpid_to_mac[cur_server_leaf_dpid]

                spine_datapath = self.datapaths[cur_spine_dpid]
                server_leaf_datapath = self.datapaths[cur_server_leaf_dpid]

                out_port_client_leaf_to_spine = self.mac_to_port[dpid][cur_spine_dpid]
                out_port_spine_to_server_leaf = self.mac_to_port[cur_spine_dpid][cur_server_leaf_dpid]
                out_port_server_leaf_to_server = self.mac_to_port[cur_server_leaf_dpid][cur_target_server_mac]

                out_port_spine_to_client_leaf = self.mac_to_port[cur_spine_dpid][dpid]
                out_port_server_leaf_to_spine = self.mac_to_port[cur_server_leaf_dpid][cur_spine_dpid]

                self.logger.info("Current Path: " + src + " -> " + str(dpid) + " -> " + str(cur_spine_dpid) +
                    " -> " + str(cur_server_leaf_dpid) + " -> " + self.dpid_to_mac[cur_server_leaf_dpid])            

                # Client Switch -> Spine Switch

                match_send = parser.OFPMatch(
                    # in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_src=src,
                    eth_dst=dst,
                    ip_proto=ip_header.proto,
                    ipv4_src=ip_header.src,
                    ipv4_dst=ip_header.dst,
                    tcp_src=tcp_header.src_port,
                    tcp_dst=tcp_header.dst_port
                )

                actions = [parser.OFPActionOutput(out_port_client_leaf_to_spine)]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(datapath, match_send, actions, idle_timeout=5, cookie=cookie)

                # Spine Switch -> Server Switch

                actions = [parser.OFPActionOutput(out_port_spine_to_server_leaf)]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(spine_datapath, match_send, actions, idle_timeout=5, cookie=cookie, meter_id=99)

                # Server Switch -> Server Host

                actions = [
                    parser.OFPActionSetField(ipv4_src=self.controller_ip),
                    parser.OFPActionSetField(eth_dst=cur_target_server_mac),
                    parser.OFPActionSetField(ipv4_dst=self.mac_to_ip[cur_target_server_mac]),
                    parser.OFPActionOutput(out_port_server_leaf_to_server)
                ]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(server_leaf_datapath, match_send, actions, idle_timeout=5, cookie=cookie)

                # Client Switch -> Client Host (Reverse)

                match_receive = parser.OFPMatch(
                    eth_type=eth.ethertype,
                    eth_src=cur_target_server_mac,
                    eth_dst=self.controller_mac,
                    ip_proto=ip_header.proto,
                    ipv4_src=self.mac_to_ip[cur_target_server_mac],
                    ipv4_dst=self.controller_ip,
                    tcp_src=tcp_header.dst_port,
                    tcp_dst=tcp_header.src_port
                )

                actions = [
                    parser.OFPActionSetField(eth_src=self.controller_mac),
                    parser.OFPActionSetField(ipv4_src=self.controller_ip),
                    parser.OFPActionSetField(eth_dst=eth.src),
                    parser.OFPActionSetField(ipv4_dst=ip_header.src),
                    parser.OFPActionOutput(in_port)
                ]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(datapath, match_receive, actions, idle_timeout=5, cookie=cookie)
                                
                # Spine Switch -> Client Switch (Reverse)

                actions = [parser.OFPActionOutput(out_port_spine_to_client_leaf)]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(spine_datapath, match_receive, actions, idle_timeout=5, cookie=cookie)
                

                # Server Switch -> Spine Switch (Reverse)

                actions = [parser.OFPActionOutput(out_port_server_leaf_to_spine)]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(server_leaf_datapath, match_receive, actions, idle_timeout=5, cookie=cookie)

            if ip_header.dst == self.controller_ip and ip_header.proto == in_proto.IPPROTO_UDP:
                udp_header = pkt.get_protocols(udp.udp)[0]
                

                # Client Switch -> Spine Switch

                match_send = parser.OFPMatch(
                    # in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_src=src,
                    eth_dst=dst,
                    ip_proto=ip_header.proto,
                    ipv4_src=ip_header.src,
                    ipv4_dst=ip_header.dst,
                    udp_src=udp_header.src_port,
                    udp_dst=udp_header.dst_port
                )

                actions = [parser.OFPActionOutput(2)]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(self.datapaths[2], match_send, actions, idle_timeout=5, cookie=cookie)

                # Spine Switch -> Server Switch

                actions = [parser.OFPActionOutput(1)]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(self.datapaths[3], match_send, actions, idle_timeout=5, cookie=cookie)

                # Server Switch -> Server Host

                actions = [
                    parser.OFPActionSetField(ipv4_src=self.controller_ip),
                    parser.OFPActionSetField(eth_dst=self.target_mac),
                    parser.OFPActionSetField(ipv4_dst=self.target_ip),
                    parser.OFPActionOutput(1)
                ]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(self.datapaths[1], match_send, actions, idle_timeout=5, cookie=cookie)

                # Client Switch -> Client Host (Reverse)

                match_receive = parser.OFPMatch(
                    eth_type=eth.ethertype,
                    eth_src=self.target_mac,
                    eth_dst=self.controller_mac,
                    ip_proto=ip_header.proto,
                    ipv4_src=self.target_ip,
                    ipv4_dst=self.controller_ip,
                    udp_src=udp_header.dst_port,
                    udp_dst=udp_header.src_port
                )

                actions = [
                    parser.OFPActionSetField(eth_src=self.controller_mac),
                    parser.OFPActionSetField(ipv4_src=self.controller_ip),
                    parser.OFPActionSetField(eth_dst=eth.src),
                    parser.OFPActionSetField(ipv4_dst=ip_header.src),
                    parser.OFPActionOutput(in_port)
                ]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(self.datapaths[2], match_receive, actions, idle_timeout=5, cookie=cookie)
                                
                # Spine Switch -> Client Switch (Reverse)

                actions = [
                    parser.OFPActionOutput(2)
                ]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(self.datapaths[3], match_receive, actions, idle_timeout=5, cookie=cookie)
                

                # Server Switch -> Spine Switch (Reverse)

                actions = [
                    parser.OFPActionOutput(2)
                ]

                cookie = random.randint(0, 0xffffffffffffffff)

                self.add_flow(self.datapaths[1], match_receive, actions, idle_timeout=5, cookie=cookie)                

            if self.is_rr == True:
                self.cur_server_leaf_index += 1
                if self.cur_server_leaf_index == len(self.server_leaf_dpids):
                    self.cur_server_leaf_index = 0

                self.cur_spine_index += 1
                if self.cur_spine_index == len(self.spine_dpids):
                    self.cur_spine_index = 0

            return
           



        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD

        # actions = [parser.OFPActionOutput(out_port)]

        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #     # verify if we have a valid buffer_id, if yes avoid to send both
        #     # flow_mod & packet_out
        #     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        #         self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath, 1, match, actions)
        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data

        # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                           in_port=in_port, actions=actions, data=data)
        # datapath.send_msg(out)

    # @set_ev_cls(event.EventSwitchEnter)
    # def get_topology_data(self, ev):

        # hosts_list = get_host(self,None)
        # switch_list = get_switch(self, None)
        # switches=[switch.dp.id for switch in switch_list]
        