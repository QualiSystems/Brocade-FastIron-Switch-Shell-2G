#!/usr/bin/python
# -*- coding: utf-8 -*-


from cloudshell.networking.brocade.fastiron.flows.fastiron_autoload_flow import BrocadeFastIronSnmpAutoloadFlow
from cloudshell.networking.brocade.runners.brocade_autoload_runner import BrocadeAutoloadRunner


class BrocadeFastIronAutoloadRunner(BrocadeAutoloadRunner):
    @property
    def autoload_flow(self):
        return BrocadeFastIronSnmpAutoloadFlow(self.snmp_handler, self._logger)
