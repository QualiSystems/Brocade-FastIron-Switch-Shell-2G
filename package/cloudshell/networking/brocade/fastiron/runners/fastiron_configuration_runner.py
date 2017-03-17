#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.networking.brocade.runners.brocade_configuration_runner import BrocadeConfigurationRunner
from cloudshell.networking.brocade.fastiron.flows.fastiron_restore_flow import BrocadeFastIronRestoreFlow
from cloudshell.networking.brocade.fastiron.flows.fastiron_save_flow import BrocadeFastIronSaveFlow


class BrocadeFastIronConfigurationRunner(BrocadeConfigurationRunner):
    @property
    def restore_flow(self):
        return BrocadeFastIronRestoreFlow(cli_handler=self.cli_handler, logger=self._logger)

    @property
    def save_flow(self):
        return BrocadeFastIronSaveFlow(cli_handler=self.cli_handler, logger=self._logger)
