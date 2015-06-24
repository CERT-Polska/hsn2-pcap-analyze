# Copyright (c) NASK
#
# This file is part of HoneySpider Network 2.0.
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

import sys
import ConfigParser
import logging


class Config():
    config = None

    def getConfig(self):
        self.config = ConfigParser.ConfigParser()
        try:
            self.config.readfp(
                open("/etc/hsn2/pcap-analyze/pcap-analyze.conf"))
        except IOError:
            logging.warn(
                "Cannot open '/etc/hsn2/pcap-analyze/pcap-analyze.conf'. Exiting...")
            sys.exit(2)
        return self.config

    def getElement(self, name):
        element = None
        try:
            element = self.config.get("pcap-analyze", name)
        except:
            pass
        return element

    def getSaveIp(self):
        saveIp = self.getElement("save_ip")
        if saveIp is not None and saveIp.lower().strip() == "true":
            return True
        return False

    def getSaveDns(self):
        saveDns = self.getElement("save_dns")
        if saveDns is not None and saveDns.lower().strip() == "true":
            return True
        return False

    def hasProtocolFilter(self):
        protocolFilter = self.getElement("protocol_filter")
        return protocolFilter is not None

    def getProtocolFilter(self):
        return self.getElement("protocol_filter").strip()

    def getProtocolFields(self):
        protocolFields = self.getElement("protocol_fields").strip()
        if protocolFields is not None:
            return protocolFields
        return ""

    def getProtocolUnique(self):
        protocolUnique = self.getElement("protocol_unique")
        if protocolUnique is not None and protocolUnique.lower().strip() == "true":
            return True
        return False

    def getWhiteList(self):
        filters = []
        allowed_traffic = self.getElement("allowed_traffic")
        if self.getElement("allowed_traffic") is None:
            return ""

        try:
            f = open(allowed_traffic, 'r')
            for line in f:
                line = line.strip()
                if len(line) == 0 or line[0] == "#":
                    continue
                filters.append(line)
            f.close()
            return " or ".join(filters)
        except IOError:
            logging.warn(
                "Cannot open '/etc/hsn2/pcap-analyze/pcap-analyze-whitelist.conf'. Exiting...")
            sys.exit(2)
