/*
 * Copyright 2017-present Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ee513;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.net.Device;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.host.HostService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.device.DeviceService;

import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Optional;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private MacAddress mac1 = new MacAddress(new byte[] {0,0,0,0,0,1});
    private MacAddress mac2 = new MacAddress(new byte[] {0,0,0,0,0,2});
    private MacAddress mac3 = new MacAddress(new byte[] {0,0,0,0,0,3});

    private String ip1 = "10.0.0.1";
    private String ip2 = "10.0.0.2";
    private String ip3 = "10.0.0.3";

    private IpAddress ipA1 = Ip4Address.valueOf(ip1);
    private IpAddress ipA2 = Ip4Address.valueOf(ip2);
    private IpAddress ipA3 = Ip4Address.valueOf(ip3);

    private IpPrefix ipP1 = IpPrefix.valueOf(ipA1, IpPrefix.MAX_INET_MASK_LENGTH);
    private IpPrefix ipP2 = IpPrefix.valueOf(ipA2, IpPrefix.MAX_INET_MASK_LENGTH);
    private IpPrefix ipP3 = IpPrefix.valueOf(ipA3, IpPrefix.MAX_INET_MASK_LENGTH);

    private int flowTimeout = 100;
    private int flowPriority = 10;

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;


    private ApplicationId appId;

    private PacketProcessor processor;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.redirection.app");

        processor = new RedirectionPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(10));

        log.info("Redirection Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        flowRuleService.removeFlowRulesById(appId);
        log.info("Redirection Stopped");
    }



    private class RedirectionPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context == null || context.inPacket() == null || context.inPacket().parsed() == null) {
                return;
            }

            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();


            if (ethPkt == null) {
                return;
            }

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }


            // builders
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();

            selector.matchInPort(context.inPacket().receivedFrom().port());
            selector.matchEthSrc(ethPkt.getSourceMAC())
                    .matchEthDst(ethPkt.getDestinationMAC());


            HostId id = HostId.hostId(ethPkt.getDestinationMAC());

            boolean redirected = false;

            // Check if redirection needed
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();

                int dstIp = ipv4Packet.getDestinationAddress();
                String dstIpS = IPv4.fromIPv4Address(dstIp);
                int srcIp = ipv4Packet.getSourceAddress();
                String srcIpS = IPv4.fromIPv4Address(srcIp);

                if (ipv4Protocol == IPv4.PROTOCOL_TCP) {

                    //log.info("PACKET IN : " + srcIpS + " -> " + dstIpS + " || " + ethPkt.getSourceMAC() + " -> " + ethPkt.getDestinationMAC());

                    if (srcIpS.equals(ip1) && dstIpS.equals(ip2)) {
                        // h1 -> h2 TCP flow
                        // redirect to h3 : change ip dst to h3

                        //log.info("Creating rule for h1->h2 > h1->h3");

                        selector.matchIPSrc(IpPrefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchIPDst(IpPrefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchIPProtocol(IPv4.PROTOCOL_TCP);


                        ipv4Packet.setDestinationAddress(ip3);
                        ethPkt.setDestinationMACAddress(mac3);


                        treatment.setIpDst(IpAddress.valueOf(ipv4Packet.getDestinationAddress()))
                                .setEthDst(ethPkt.getDestinationMAC());

                        id = HostId.hostId(mac3); // set destination for forwarding

                        redirected = true;

                    } else if (srcIpS.equals(ip3) && dstIpS.equals(ip1)) {
                        // h3 -> h1 TCP flow
                        // redirect from h2 : change ip src to h2

                        //log.info("Creating rule for h3->h1 > h2->h1");

                        selector.matchIPSrc(IpPrefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchIPDst(IpPrefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                                .matchIPProtocol(IPv4.PROTOCOL_TCP);

                        ipv4Packet.setSourceAddress(ip2);
                        ethPkt.setSourceMACAddress(mac2);

                        treatment.setIpSrc(IpAddress.valueOf(ipv4Packet.getSourceAddress()))
                                .setEthSrc(ethPkt.getSourceMAC());

                        redirected = true;
                    }

                }
            }

            treatment.immediate();

            // Do not process link-local addresses in any way.
            if (id.mac().isLinkLocal()) {
                return;
            }

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);
            if (dst == null) {
                flood(context);
                return;
            }

            // Are we on an edge switch that our destination is on? If so,
            // simply forward out to the destination and bail.
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(context, dst.location().port(), selector, treatment, redirected);
                }
                return;
            }

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                            pkt.receivedFrom().deviceId(),
                            dst.location().deviceId());
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
                flood(context);
                return;
            }

            // Otherwise, pick a path that does not lead back to where we
            // came from; if no such path, flood and bail.
            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                        pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context);
                return;
            }

            // Otherwise forward and be done with it.
            installRule(context, path.src().port(), selector, treatment, redirected);

        }
    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        Path lastPath = null;
        for (Path path : paths) {
            lastPath = path;
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return lastPath;
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {

            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber, TrafficSelector.Builder selectorBuilder, TrafficTreatment.Builder treatmentBuilder, boolean redirected) {

        Ethernet inPkt = context.inPacket().parsed();

        // If ARP packet then forward directly to output port
        if (inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber);
            return;
        }

        treatmentBuilder.setOutput(portNumber);

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatmentBuilder.build())
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                forwardingObjective);


        if (!redirected) {
            packetOut(context, portNumber);
        } else {
            // It has to be IPv4 & TCP
            Ethernet packet = context.inPacket().parsed();
            IPv4 ipv4Packet = (IPv4) packet.getPayload();
            TCP tcpPacket = (TCP) ipv4Packet.getPayload();

            ipv4Packet.resetChecksum();
            packet.resetChecksum();
            tcpPacket.resetChecksum();

            ByteBuffer buffer = ByteBuffer.wrap(packet.serialize());

            // send the packet
            packetService.emit(new DefaultOutboundPacket(
                    context.inPacket().receivedFrom().deviceId(),
                    treatmentBuilder.build(),
                    buffer)
            );

            Iterable<Device> devices = deviceService.getDevices();
            // Install rules on every switch
            for (Device d : devices) {
                flowObjectiveService.forward(d.id(),
                        forwardingObjective);
            }
        }

    }

}