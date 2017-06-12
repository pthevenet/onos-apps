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



import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.IPacket;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Data;


import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Optional;


/**
 * Firewall
 */
@Component(immediate = true)
public class AppComponent {


    private int flowTimeout = 10;
    private int flowPriority = 10;
    private static final int PRIORITY = 128;


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


    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;

    private PacketProcessor processor;


    // Selector for TCP traffic that is to be intercepted

    private final TrafficSelector intercept = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_TCP)
            .build();

    private List<Entry> whiteList;

    private List<FtpActiveInitInfo> pendingActive;

    private List<FtpPassiveInitInfo> pendingPassive;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.firewall.app");

        processor = new FirewallPacketProcessor();

        packetService.addProcessor(processor, PRIORITY);

        // Make the FTP in/out packets always be controlled by the controller (no fixed rule)
        packetService.requestPackets(intercept, PacketPriority.CONTROL, appId,
                Optional.empty());

        this.whiteList = new ArrayList<>();
        this.pendingActive = new ArrayList<>();
        this.pendingPassive = new ArrayList<>();

        log.info("Firewall Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        flowRuleService.removeFlowRulesById(appId);

        log.info("Firewall Stopped");
    }

    private class FirewallPacketProcessor implements PacketProcessor {


        public void processTcpDst21(String data, long srcIp, int srcPort, long dstIp, int dstPort) {
            // accept and check for "PORT M" command (active mode)
            // Check Active PORT command
            String[] spaces = data.split(" ");
            if (spaces.length >= 2 && spaces[0].equals("PORT")) {

                // dstPort = 21 AND payload = "PORT ..." => ACTIVE MODE request by client

                String[] commas = spaces[1].split(",");
                if (commas.length >= 6) {
                    try {
                        int p1 = Integer.parseInt(commas[4].trim());
                        int p2 = Integer.parseInt(commas[5].trim());
                        int port = p1 * 16 * 16 + p2; // conversion hex -> dec

                        // Add to pending Active Connections
                        FtpActiveInitInfo activeInfo = new FtpActiveInitInfo(dstIp, srcIp, port);

                        if (!pendingActive.contains(activeInfo)) {
                            pendingActive.add(activeInfo);
                            activeInfo.validate();
                            log.info("New Pending Active : " + activeInfo);
                        }

                    } catch (NumberFormatException e) {
                        // ignore
                    }
                }
            }
            // Check Passive PASV command
            if (data.trim().equals("PASV")) {
                FtpPassiveInitInfo passiveInfo = new FtpPassiveInitInfo(srcIp, dstIp, 0);
                if (!pendingPassive.contains(passiveInfo)) {
                    pendingPassive.add(passiveInfo);
                    log.info("New Pending Passive : " + passiveInfo);
                }
            }
        }

        public void processTcpSrc21(String data, long srcIp, int srcPort, long dstIp, int dstPort) {
            // accept, check for PASSIVE mode request, and validate pending Active mode connections

            // Check if this is a Passive mode response
            String[] openPa = data.split("\\(");
            if (openPa.length >= 2 && openPa[0].trim().equals("227 Entering passive mode")) {
                String[] closePa = openPa[1].split("\\)");
                if (closePa.length >= 1) {

                    // srcPort = 21 AND payload = "227 Entering passive mode (ip,port)" => PASSIVE MODE

                    String[] commas = closePa[0].split(",");

                    if (commas.length >= 6) {
                        try {
                            int p1 = Integer.parseInt(commas[4].trim());
                            int p2 = Integer.parseInt(commas[5].trim());
                            int port = p1 * 16 * 16 + p2; // conversion hex -> dec

                            Entry e = new Entry(dstIp, 0, srcIp, port);

                            // Validate the pending connection
                            for (FtpPassiveInitInfo pendingInfo : pendingPassive) {
                                if (pendingInfo.ipCorresponds(srcIp, dstIp)) {
                                    if (!pendingInfo.isValidated()) {
                                        // Validate
                                        pendingInfo.setServerPort(port);
                                        pendingInfo.validate();
                                        log.info("Validate : " + pendingInfo);
                                    }
                                }
                            }

                        } catch (NumberFormatException e) {
                            // ignore
                        }
                    }

                }
            }

        }

        public boolean processTcpOthers(String data, long srcIp, int srcPort, long dstIp, int dstPort) {
            boolean forward = false;
            FtpActiveInitInfo testA1 = new FtpActiveInitInfo(srcIp, dstIp, dstPort);
            testA1.validate();
            FtpActiveInitInfo testA2 = new FtpActiveInitInfo(dstIp, srcIp, srcPort);
            testA2.validate();
            FtpPassiveInitInfo testP1 = new FtpPassiveInitInfo(srcIp, dstIp, dstPort);
            testP1.validate();
            FtpPassiveInitInfo testP2 = new FtpPassiveInitInfo(dstIp, srcIp, srcPort);
            testP2.validate();

            Entry e = new Entry(srcIp, srcPort, dstIp, dstPort);

            if (whiteList.contains(e)) {
                log.info("Flow whitelisted");
                forward = true;
            } else if (pendingActive.contains(testA1)) {
                whiteList.add(e);
                log.info("Active Whitelisted : " + testA1 + " with server port : " + srcPort);
                forward = true;
            } else if (pendingActive.contains(testA2)) {
                whiteList.add(e);
                log.info("Active Whitelisted : " + testA2 + " with server port : " + dstPort);
                forward = true;
            } else if (pendingPassive.contains(testP1)) {
                whiteList.add(e);
                log.info("Passive Whitelisted : " + testP1 + " with client port : " + srcPort);
                forward = true;
            } else if (pendingPassive.contains(testP2)) {
                whiteList.add(e);
                log.info("Passive Whitelisted : " + testP2 + " with client port : " + dstPort);
                forward = true;
            } else {
                // do not forward
                forward = false;
            }

            return forward;
        }

        public boolean processTcpPacket(TCP tcpPacket, long srcIp, long dstIp) {

            boolean forward = false;
            int srcPort = tcpPacket.getSourcePort();
            int dstPort = tcpPacket.getDestinationPort();

            Data appPkt = (Data) tcpPacket.getPayload();
            String data = new String(appPkt.getData()); // data is the String of the tcp payload (application data)

            /*
            log.info("Port " + srcPort + " -> " + dstPort);
            log.info("Payload : " + data);
            */

            if (dstPort == 21) {
                processTcpDst21(data, srcIp, srcPort, dstIp, dstPort);
                forward = true;
            } else if (srcPort == 21) {
                processTcpSrc21(data, srcIp, srcPort, dstIp, dstPort);
                forward = true;
            } else {
                forward = processTcpOthers(data, srcIp, srcPort, dstIp, dstPort);
            }

            return forward;

        }


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

            HostId id = HostId.hostId(ethPkt.getDestinationMAC());

            // Do not process link-local addresses in any way.
            if (id.mac().isLinkLocal()) {
                return;
            }

            // builders
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();

            TCP tcpPacket = null;
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4 && ((IPv4) ethPkt.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP) {
                IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
                tcpPacket = (TCP) ipv4Packet.getPayload();

                long dstIp = ipv4Packet.getDestinationAddress();
                long srcIp = ipv4Packet.getSourceAddress();

                if (tcpPacket != null) {

                    boolean forward = processTcpPacket(tcpPacket, srcIp, dstIp);

                    if (!forward) {
                        //log.info("BLOCK TCP PACKET");
                        context.block();
                        return;
                    }

                    selector.matchIPSrc(IpPrefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH))
                            .matchIPDst(IpPrefix.valueOf(ipv4Packet.getDestinationAddress(), Ip4Prefix.MAX_MASK_LENGTH));

                    selector.matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));

                } else {
                    context.block();
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
                        installRule(context, dst.location().port(), selector, treatment);
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
                installRule(context, path.src().port(), selector, treatment);

            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4 && ((IPv4) ethPkt.getPayload()).getProtocol() == IPv4.PROTOCOL_UDP) {
                context.block();
                return;
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                context.block();
                return;
            } else {
                //context.block();
                return;
            }
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
    private void installRule(PacketContext context, PortNumber portNumber, TrafficSelector.Builder selectorBuilder, TrafficTreatment.Builder treatmentBuilder) {

        Ethernet inPkt = context.inPacket().parsed();

        // If ARP packet then forward directly to output port
        if (inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber);
            return;
        }

        selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC());

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

        //log.info("FORWADING RULE : " + forwardingObjective);

        packetOut(context, portNumber);

    }

}
