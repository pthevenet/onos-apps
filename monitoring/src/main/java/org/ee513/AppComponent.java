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

import org.onosproject.net.Device;
import org.onosproject.net.Port;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.statistic.FlowStatisticService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.statistic.TypedFlowEntryWithLoad;
import org.onosproject.net.flow.*;
import org.onosproject.net.statistic.FlowEntryWithLoad;
import org.onosproject.net.flow.TypedStoredFlowEntry;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.instructions.Instruction;
import org.onlab.packet.IpAddress;


import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Monitoring
 */
@Component(immediate = true)
public class AppComponent {

    private final long RATE_LIMIT = 10_485_760; // 10 MebiBytes //10_000_000;

    private final Logger log = LoggerFactory.getLogger(getClass());


    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowStatisticService flowStatsService;


    private ApplicationId appId;

    private Iterable<Device> devices;

    private Map<Device, Map<ConnectPoint,List<FlowEntryWithLoad>>> stats;

    private Timer timer;
    private TimerTask myTask;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.monitoring.app");

        devices = deviceService.getDevices();


        timer = new Timer();
        myTask = new TimerTask() {
            @Override
            public void run() {
                stats = new HashMap<>();

                for (Device d : devices) {
                    Instruction.Type inInstructionType = null;
                    FlowEntry.FlowLiveType inLiveType = null;
                    Map<ConnectPoint, List<FlowEntryWithLoad>> deviceEntry = flowStatsService.loadAllByType(d, inLiveType, inInstructionType);
                    stats.put(d, deviceEntry);
                }

                for (Map.Entry<Device, Map<ConnectPoint,List<FlowEntryWithLoad>>> statsEntry : stats.entrySet()) {
                    Device d = statsEntry.getKey();
                    Map<ConnectPoint,List<FlowEntryWithLoad>> deviceEntry = statsEntry.getValue();

                    //log.info("Device : " + d.id());

                    for (Map.Entry<ConnectPoint, List<FlowEntryWithLoad>> connectPointEntry : deviceEntry.entrySet()) {
                        ConnectPoint cp = connectPointEntry.getKey();

                        List<FlowEntryWithLoad> flowEntryList = connectPointEntry.getValue();

                        //log.info("connect point : " + cp);
                        //log.info("len : " + flowEntryList.size());

                        for (FlowEntryWithLoad flowEntry : flowEntryList) {

                            // if load > ...
                            if (flowEntry.load().rate() >= RATE_LIMIT) {

                                StoredFlowEntry entry = flowEntry.storedFlowEntry();


                                log.info("Flow detected with rate : " + flowEntry.load().rate() + " B/s");
                                // Parse flow rule and extract IPsrc
                                String[] s = entry.toString().split("IPV4_SRC:");
                                if (s.length >= 2) {
                                    String[] ss = s[1].split(",");
                                    if (ss.length >= 1) {
                                        log.info("Sender : " + ss[0]);
                                    }
                                }
                                log.info("Flow rule : \n" + entry);
                            }

                        }
                    }
                }

            }
        };
        timer.schedule(myTask, 1000, 1000);

        myTask.run();


        log.info("Monitoring Started");


    }

    @Deactivate
    protected void deactivate() {
        myTask.cancel();
        log.info("Monitoring Stopped");
    }


}



