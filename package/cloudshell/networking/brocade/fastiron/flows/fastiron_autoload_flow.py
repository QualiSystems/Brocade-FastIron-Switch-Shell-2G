#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.networking.brocade.fastiron.autoload.brocade_fastiron_snmp_autoload import BrocadeFastIronSNMPAutoload
from cloudshell.networking.brocade.flows.brocade_autoload_flow import BrocadeSnmpAutoloadFlow


class BrocadeFastIronSnmpAutoloadFlow(BrocadeSnmpAutoloadFlow):
    def execute_flow(self, supported_os, shell_name, shell_type, resource_name):
        with self._snmp_handler.get_snmp_service() as snpm_service:
            snmp_autoload = BrocadeFastIronSNMPAutoload(snpm_service,
                                                        shell_name,
                                                        shell_type,
                                                        resource_name,
                                                        self._logger)
            return snmp_autoload.discover(supported_os)
