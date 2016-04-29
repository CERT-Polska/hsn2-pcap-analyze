#!/usr/bin/python -tt

# Copyright (c) NASK
#
# This file is part of HoneySpider Network 2.1.
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import re

from hsn2_commons import hsn2objectwrapper as ow
from hsn2_commons.hsn2osadapter import ObjectStoreException
from hsn2_commons.hsn2taskprocessor import HSN2TaskProcessor
from hsn2_commons.hsn2taskprocessor import ParamException
from hsn2_pcap_analyze.config import Config
from hsn2_pcap_analyze.external import External


class PcapAnalyzeTaskProcessor(HSN2TaskProcessor):
    parser = None
    external = None
    regex = re.compile(
        "(?P<id>.*?)\s+(?P<time>.*?)\s+(?P<from>.+?)\s*->\s{1,3}(?P<to>.+?)\s{1,3}(?P<protocol>\w+)\s*(?P<port>\d+)(?P<rest>.*)")
    ipRegex = re.compile(
        "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", re.I)
    dnsRegex = re.compile('Running as user "root"(.*)')

    def getPcapFilePath(self):
        return self.dsAdapter.saveTmp(self.currentTask.job, self.objects[0].pcap_content.getKey())

    def getRequestList(self, pcapFilePath, whitelist):
        self.external = External()
        outputLines = self.external.runExternal(
            ["tshark", whitelist, "-r", pcapFilePath])[0].split("\n")
        result = []
        for line in outputLines:
            match = re.search(self.regex, line.strip())
            if match is None:
                continue

            tmp = {}
            tmp["id"] = int(match.group("id").strip())
            tmp["time"] = match.group("time").strip()
            tmp["from"] = match.group("from").strip()
            tmp["to"] = match.group("to").strip()
            tmp["protocol"] = match.group("protocol").strip()
            tmp["port"] = match.group("port").strip()
            tmp["rest"] = match.group("rest").strip()
            result.append(tmp)
        return result

    def processSaveIp(self, pcapFilePath):
        outputLines = self.external.runExternal(
            ["tshark", "-r", pcapFilePath, "-Tfields", "-e", "ip.addr"])[0].split("\n")
        resultSet = set()

        for line in outputLines:
            line = line.strip()
            if line == "":
                continue
            arr = line.split(",")
            for ip in arr:
                if re.match(self.ipRegex, ip) is not None:
                    resultSet.add(ip.strip())
        resultList = list()
        for ip in resultSet:
            resultList.append(ip)

        ipList = ow.toIpAddressList(resultList)
        self.objects[0].addBytes("pcap_ip", self.dsAdapter.putBytes(
            bytes(ipList.SerializeToString()), self.currentTask.job))

    def processSaveDns(self, pcapFilePath):
        outputLines = self.external.runExternal(
            ["tshark", "dns", "-r", pcapFilePath])[0].split("\n")
        resultList = list()
        for line in outputLines:
            match = re.search(self.regex, line.strip())
            if match is None:
                continue
            resultList.append(line)

        dnsList = ow.toDnsList(resultList)
        self.objects[0].addBytes("pcap_dns", self.dsAdapter.putBytes(
            bytes(dnsList.SerializeToString()), self.currentTask.job))

    def processProtocolFilter(self, pcapFilePath, protocolFilter, protocolFields, protocolUnique):
        protocolFieldsArray = protocolFields.split(",")

        def prepare(x): return x.strip()
        protocolFieldsArray = map(prepare, protocolFieldsArray)

        tsharkExec = ["tshark", protocolFilter, "-r", pcapFilePath, "-Tfields"]
        for field in protocolFieldsArray:
            tsharkExec.append("-e")
            tsharkExec.append(field)

        outputLines = self.external.runExternal(tsharkExec)[0].split("\n")

        if protocolUnique:
            resultSet = set()
            for line in outputLines:
                line = line.strip()
                if re.match(self.dnsRegex, line) or line == "":
                    continue
                resultSet.add(line)
            resultList = list()
            for elem in resultSet:
                resultList.append(elem)
        else:
            resultList = list()
            for line in outputLines:
                line = line.strip()
                if re.match(self.dnsRegex, line) or line == "":
                    continue
                resultList.append(line)

        filterList = ow.toFilterList(resultList)
        self.objects[0].addBytes("pcap_protocol_%s" % protocolFilter, self.dsAdapter.putBytes(
            bytes(filterList.SerializeToString()), self.currentTask.job))

    def taskProcess(self):
        logging.debug(self.__class__)
        logging.debug(self.currentTask)
        logging.debug(self.objects)

        if len(self.objects) == 0:
            raise ObjectStoreException(
                "Task processing didn't find task object.")

        if not self.objects[0].isSet("pcap_content"):
            raise ParamException("pcap_content param is missing.")

        configObj = Config()
        configObj.getConfig()
        whitelist = configObj.getWhiteList()
        pcapFilePath = self.getPcapFilePath()
        tsharkResultAll = self.getRequestList(pcapFilePath, "")
        tsharkResultClean = self.getRequestList(pcapFilePath, whitelist)
        cleanLen = len(tsharkResultClean)
        allLen = len(tsharkResultAll)

        pcapNetworkTrafic = (whitelist != "" and cleanLen < allLen) or (
            whitelist == "" and allLen == 0)
        self.objects[0].addBool("pcap_network_traffic", pcapNetworkTrafic)

        if configObj.getSaveIp():
            self.processSaveIp(pcapFilePath)

        if configObj.getSaveDns():
            self.processSaveDns(pcapFilePath)

        if configObj.hasProtocolFilter():
            self.processProtocolFilter(pcapFilePath, configObj.getProtocolFilter(
            ), configObj.getProtocolFields(), configObj.getProtocolUnique())

        return []

if __name__ == '__main__':
    a = PcapAnalyzeTaskProcessor()
