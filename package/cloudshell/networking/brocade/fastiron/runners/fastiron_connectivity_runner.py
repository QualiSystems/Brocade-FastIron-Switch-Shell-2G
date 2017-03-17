#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.networking.brocade.fastiron.flows.fastiron_add_vlan_flow import BrocadeFastIronAddVlanFlow
from cloudshell.networking.brocade.fastiron.flows.fastiron_remove_vlan_flow import BrocadeFastIronRemoveVlanFlow
from cloudshell.networking.brocade.runners.brocade_connectivity_runner import BrocadeConnectivityRunner


class BrocadeFastIronConnectivityRunner(BrocadeConnectivityRunner):
    IS_VLAN_RANGE_SUPPORTED = True

    @property
    def add_vlan_flow(self):
        return BrocadeFastIronAddVlanFlow(self.cli_handler, self._logger)

    @property
    def remove_vlan_flow(self):
        return BrocadeFastIronRemoveVlanFlow(self.cli_handler, self._logger)
