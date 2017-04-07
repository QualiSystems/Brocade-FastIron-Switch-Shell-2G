#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import os

from cloudshell.devices.autoload.autoload_builder import AutoloadDetailsBuilder
from cloudshell.devices.standards.networking.autoload_structure import *


class BrocadeFastIronSNMPAutoload(object):
    def __init__(self, snmp_handler, shell_name, shell_type, resource_name, logger):
        self.snmp_handler = snmp_handler
        self.shell_name = shell_name
        self.shell_type = shell_type
        self.resource_name = resource_name
        self.logger = logger

        self.port_exclude_pattern = r"stack|engine|management|mgmt|voice|foreign|cpu"

        self.elements = {}
        self.resource = GenericResource(shell_name=shell_name,
                                        shell_type=shell_type,
                                        name=resource_name,
                                        unique_id=resource_name)

    def load_additional_mibs(self):
        """ Loads specific mibs inside snmp handler """

        # Path to General Brocade MIBs
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mibs"))
        self.snmp_handler.update_mib_sources(path)

        # Path to Specific Brocade FastIron MIBs
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mibs"))
        self.snmp_handler.update_mib_sources(path)

    def discover(self, supported_os):
        """ General entry point for autoload,
        read device structure and attributes: chassis, modules, submodules, ports, port-channels and power supplies

        :return: AutoLoadDetails object
        """

        if not self._is_valid_device_os(supported_os):
            raise Exception(self.__class__.__name__, 'Unsupported device OS')

        self.logger.info("*" * 70)
        self.logger.info("Start SNMP discovery process .....")

        self.load_additional_mibs()
        self.snmp_handler.load_mib(["FOUNDRY-SN-AGENT-MIB", "FOUNDRY-SN-SWITCH-GROUP-MIB", "FOUNDRY-SN-STACKING-MIB",
                                    "FOUNDRY-SN-IP-MIB"])

        self._load_snmp_tables()

        self._get_device_details()
        self._get_chassis_info()
        self._get_power_ports_info()
        self._get_modules_info()
        self._get_ports_info()

        autoload_details = AutoloadDetailsBuilder(self.resource).autoload_details()
        self._log_autoload_details(autoload_details)
        return autoload_details

    def _log_autoload_details(self, autoload_details):
        """
        Logging autoload details
        :param autoload_details:
        :return:
        """
        self.logger.debug("-------------------- <RESOURCES> ----------------------")
        for resource in autoload_details.resources:
            self.logger.debug(
                "{0:15}, {1:20}, {2}".format(resource.relative_address, resource.name, resource.unique_identifier))
        self.logger.debug("-------------------- </RESOURCES> ----------------------")

        self.logger.debug("-------------------- <ATTRIBUTES> ---------------------")
        for attribute in autoload_details.attributes:
            self.logger.debug("-- {0:15}, {1:60}, {2}".format(attribute.relative_address, attribute.attribute_name,
                                                              attribute.attribute_value))
        self.logger.debug("-------------------- </ATTRIBUTES> ---------------------")

    def _is_valid_device_os(self, supported_os):
        """Validate device OS using snmp
            :return: True or False
        """

        system_description = self.snmp_handler.get_property('SNMPv2-MIB', 'sysDescr', '0')
        self.logger.debug('Detected system description: \'{0}\''.format(system_description))
        result = re.search(r"({0})".format("|".join(supported_os)),
                           system_description,
                           flags=re.DOTALL | re.IGNORECASE)

        if result:
            return True
        else:
            error_message = 'Incompatible driver! Please use this driver for \'{0}\' operation system(s)'. \
                format(str(tuple(supported_os)))
            self.logger.error(error_message)
            return False

    def _load_snmp_tables(self):
        """ Load all required SNMP tables """

        self.logger.info('Start loading MIB tables:')
        self.lldp_local_table = self.snmp_handler.get_table('LLDP-MIB', 'lldpLocPortDesc')
        self.lldp_remote_table = self.snmp_handler.get_table('LLDP-MIB', 'lldpRemTable')
        self.ip_v4_table = self.snmp_handler.get_table('IP-MIB', 'ipAddrTable')
        self.ip_v6_table = self.snmp_handler.get_table('IPV6-MIB', 'ipv6AddrEntry')

        self.logger.info('MIB Tables loaded successfully')

    def _get_device_details(self):
        """ Get root element attributes """

        self.logger.info("Building Root")

        vendor = "Brocade"

        self.resource.contact_name = self.snmp_handler.get_property('SNMPv2-MIB', 'sysContact', '0')
        self.resource.system_name = self.snmp_handler.get_property('SNMPv2-MIB', 'sysName', '0')
        self.resource.location = self.snmp_handler.get_property('SNMPv2-MIB', 'sysLocation', '0')
        self.resource.os_version = ""
        self.resource.model = self._get_device_model()
        self.resource.vendor = vendor

    def _get_device_model(self):
        """Get device model form snmp SNMPv2 mib

        :return: device model
        :rtype: str
        """

        result = ""
        match_name = re.search(r"::(?P<model>\S+$)", self.snmp_handler.get_property("SNMPv2-MIB", "sysObjectID", 0))
        if match_name:
            result = match_name.groupdict()["model"].capitalize()
        return result

    def _add_element(self, relative_path, resource, parent_id=""):
        """Add object data to resources and attributes lists

        :param resource: object which contains all required data for certain resource
        """

        rel_seq = relative_path.split("/")

        if len(rel_seq) == 1:  # Chassis connected directly to root
            self.resource.add_sub_resource(relative_path, resource)
        else:
            if parent_id:
                parent_object = self.elements.get(parent_id, self.resource)
            else:
                parent_object = self.elements.get("/".join(rel_seq[:-1]), self.resource)

            rel_path = re.search(r"\d+", rel_seq[-1]).group()
            parent_object.add_sub_resource(rel_path, resource)
            # parent_object.add_sub_resource(rel_seq[-1], resource)

        self.elements.update({relative_path: resource})

    def _get_chassis_info(self):
        """ Get Chassis element attributes """

        self.logger.info("Building Chassis")

        for chassis in self.snmp_handler.get_table("FOUNDRY-SN-AGENT-MIB", "snChasUnitTable").values():
            chassis_id = chassis.get("snChasUnitIndex")

            chassis_object = GenericChassis(shell_name=self.shell_name,
                                            name="Chassis {}".format(chassis_id),
                                            unique_id="{}.{}.{}".format(self.resource_name, "chassis", chassis))

            chassis_object.model = self.snmp_handler.get_property("FOUNDRY-SN-STACKING-MIB",
                                                                  "snStackingConfigUnitType",
                                                                  int(chassis_id))
            chassis_object.serial_number = chassis.get("snChasUnitSerNum", "Unknown")

            self._add_element(relative_path=chassis_id, resource=chassis_object)

        self.logger.info("Building Chassis completed")

    def _get_power_ports_info(self):
        """ Get power port elements attributes """

        self.logger.info("Start loading Power Ports")
        for power_port in self.snmp_handler.get_table("FOUNDRY-SN-AGENT-MIB", "snChasPwrSupply2Table").values():
            power_port_id = power_port.get("snChasPwrSupply2Index")
            chassis_id = power_port.get("snChasPwrSupply2Unit")
            relative_path = '{0}/PP{1}'.format(chassis_id, power_port_id)

            power_port_object = GenericPowerPort(shell_name=self.shell_name,
                                                 name="PP{0}".format(power_port_id),
                                                 unique_id="{0}.{1}.{2}".format(self.resource_name,
                                                                                "power_port",
                                                                                power_port_id))

            chassis_id = power_port.get("snChasPwrSupply2Unit")

            power_port_full_info = self.snmp_handler.get_property("FOUNDRY-SN-AGENT-MIB",
                                                                  "snChasPwrSupplyDescription",
                                                                  int(power_port_id))
            # power_port_full_info_2 = self.snmp_handler.var_binds[0]._ObjectType__args[1]._value
            if power_port_full_info.startswith("0x"):
                power_port_full_info = power_port_full_info[2:].decode("hex")

            matched = re.match(r"(?P<descr>.+)"
                               r"Model Number:(?P<port_model>.+)"
                               r"Serial Number:(?P<serial_number>.+)"
                               r"Firmware Ver:(?P<version>.+)", power_port_full_info, re.DOTALL)

            if matched:
                power_port_object.model = matched.groupdict()["port_model"].strip()
                power_port_object.port_description = matched.groupdict()["descr"].strip()
                power_port_object.version = matched.groupdict()["version"].strip()
                power_port_object.serial_number = matched.groupdict()["serial_number"].strip()

            else:
                matched = re.match(r"(?P<descr>.+)"
                                   r"Model Number:(?P<port_model>.+)"
                                   r"Serial Number:(?P<serial_number>.+)"
                                   r"Firmware Ver:(?P<version>.+)", power_port_full_info.decode("hex"), re.DOTALL)
                if matched:
                    power_port_object.model = matched.groupdict()["port_model"].strip()
                    power_port_object.port_description = matched.groupdict()["descr"].strip()
                    power_port_object.version = matched.groupdict()["version"].strip()
                    power_port_object.serial_number = matched.groupdict()["serial_number"].strip()
                else:
                    power_port_object.model = ""
                    power_port_object.port_description = ""
                    power_port_object.version = ""
                    power_port_object.serial_number = ""

            self._add_element(relative_path=relative_path, resource=power_port_object, parent_id=chassis_id)

        self.logger.info("Building Power Ports completed")

    def _get_modules_info(self):
        """ Set attributes for all discovered modules """

        self.logger.info("Building Modules")
        for module in self.snmp_handler.get_table("FOUNDRY-SN-AGENT-MIB", "snAgentBrd2Table").values():
            module_id = module.get("snAgentBrd2Slot")
            parent_id = module.get("snAgentBrd2Unit")
            relative_path = "{0}/{1}".format(parent_id, module_id)

            module_object = GenericModule(shell_name=self.shell_name,
                                          name="Module {}".format(module_id),
                                          unique_id="{0}.{1}.{2}".format(self.resource_name, "module", module_id))

            module_serial_number = self.snmp_handler.get_property("FOUNDRY-SN-AGENT-MIB",
                                                                  "snAgentBrdSerialNumber",
                                                                  int(module_id))
            if module_serial_number.startswith("0x"):
                module_serial_number = module_serial_number[2:].decode("hex")
            elif "no such object" in module_serial_number.lower():
                module_serial_number = ""

            module_object.model = module.get("snAgentBrd2MainBrdDescription")
            module_object.version = ""
            module_object.serial_number = module_serial_number

            self._add_element(relative_path=relative_path, resource=module_object, parent_id=parent_id)

        self.logger.info("Building Modules completed")

    def _get_ports_info(self):
        """ Get port elements attributes """

        self.logger.info("Building Ports")
        port_index_mapping = {int(value["snSwPortIfIndex"]): key
                              for key, value in
                              self.snmp_handler.get_table("FOUNDRY-SN-SWITCH-GROUP-MIB", "snSwPortIfIndex").iteritems()}

        for port_id, port_name in self.snmp_handler.get_table("IF-MIB", "ifName").iteritems():
            if not re.search(self.port_exclude_pattern, port_name.get("ifName", ""), re.IGNORECASE):
                interface_name = self.snmp_handler.get_property("IF-MIB", "ifName", int(port_id)).replace("/", "-")

                relative_path = self.snmp_handler.get_property("FOUNDRY-SN-SWITCH-GROUP-MIB",
                                                               "snSwPortDescr",
                                                               port_index_mapping[port_id])

                port_object = GenericPort(shell_name=self.shell_name,
                                          name=interface_name.replace("/", "-"),
                                          unique_id="{0}.{1}.{2}".format(self.resource_name, "port", port_id))

                port_object.port_description = self.snmp_handler.get_property("IF-MIB", "ifAlias", int(port_id))
                port_object.l2_protocol_type = self.snmp_handler.get_property("IF-MIB", "ifType", int(port_id)).replace("/", "").replace("'", "")
                port_object.mac_address = self.snmp_handler.get_property("IF-MIB", "ifPhysAddress", int(port_id))
                port_object.mtu = self.snmp_handler.get_property("IF-MIB", "ifMtu", int(port_id))
                port_object.bandwidth = self.snmp_handler.get_property("IF-MIB", "ifHighSpeed", int(port_id))
                port_object.ipv4_address = self._get_ipv4_interface_address(int(port_id))
                port_object.ipv6_address = self._get_ipv6_interface_address(int(port_id))
                port_object.duplex = self._get_duplex(int(port_id))
                port_object.auto_negotiation = self._get_auto_negotiation(int(port_id))
                port_object.adjacent = self._get_auto_negotiation(port_id)

                self._add_element(relative_path=relative_path, resource=port_object)
                self.logger.info("Added Interface '{}'".format(interface_name))

        self.logger.info("Building Ports completed")

    def _get_adjacent(self, port_id):
        """Get connected device interface and device name to the specified port id, using cdp or lldp protocols

        :param port_id: port index in ifTable
        :return: device's name and port connected to port id
        """

        result = ''
        if self.lldp_remote_table:
            for key, value in self.lldp_local_table.iteritems():
                interface_name = self.snmp_handler.get_property("IF-MIB", "ifName", int(port_id))
                if interface_name == '':
                    break
                if 'lldpLocPortDesc' in value and interface_name in value['lldpLocPortDesc']:
                    if 'lldpRemSysName' in self.lldp_remote_table and 'lldpRemPortDesc' in self.lldp_remote_table:
                        result = '{0} through {1}'.format(self.lldp_remote_table[key]['lldpRemSysName'],
                                                          self.lldp_remote_table[key]['lldpRemPortDesc'])
        return result

    def _get_duplex(self, port_num):
        """ Determine interface duplex

        :param port_num: port index in snSwPortInfoTable
        :return: Full or Half
        """

        if "fullDuplex" in self.snmp_handler.get_property("FOUNDRY-SN-SWITCH-GROUP-MIB",
                                                          "snSwPortInfoChnMode",
                                                          port_num):
            return "Full"
        return "Half"

    def _get_auto_negotiation(self, port_id):
        """ Determine interface auto negotiation

        :param port_id: port index in ifTable
        :return: "True" or "False"
        """

        try:
            auto_negotiation = self.snmp_handler.get(('MAU-MIB', 'ifMauAutoNegAdminStatus', port_id, 1)).values()[0]
            if "enabled" in auto_negotiation.lower():
                return "True"
        except Exception as e:
            self.logger.error('Failed to load auto negotiation property for interface {0}'.format(e.message))
        return "False"

    def _get_ip_interface_details(self, port_index):
        """Get IP address details for provided port

        :param port_index: port index in ifTable
        :return interface_details: detected info for provided interface dict{'IPv4 Address': '', 'IPv6 Address': ''}
        """

        if self.ip_v4_table and len(self.ip_v4_table) > 1:
            for key, value in self.ip_v4_table.iteritems():
                if 'ipAdEntIfIndex' in value and int(value['ipAdEntIfIndex']) == port_index:
                    return key

        if self.ip_v6_table and len(self.ip_v6_table) > 1:
            for key, value in self.ip_v6_table.iteritems():
                if 'ipAdEntIfIndex' in value and int(value['ipAdEntIfIndex']) == port_index:
                    return key

    def _get_ipv4_interface_address(self, port_index):
        """ Get IPv4 address details for provided port

        :param port_index: port index in ifTable
        :return interface ipv4 address
        """

        if self.ip_v4_table and len(self.ip_v4_table) > 1:
            for key, value in self.ip_v4_table.iteritems():
                if 'ipAdEntIfIndex' in value and int(value['ipAdEntIfIndex']) == port_index:
                    return key
        return ""

    def _get_ipv6_interface_address(self, port_index):
        """ Get IPv6 address details for provided port

        :param port_index: port index in ifTable
        :return interface ipv6 address
        """

        if self.ip_v6_table and len(self.ip_v6_table) > 1:
            for key, value in self.ip_v6_table.iteritems():
                if 'ipAdEntIfIndex' in value and int(value['ipAdEntIfIndex']) == port_index:
                    return key
        return ""
