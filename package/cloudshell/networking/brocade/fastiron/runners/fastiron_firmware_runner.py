#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.networking.brocade.fastiron.flows.fastiron_load_firmware_flow import BrocadeFastIronLoadFirmwareFlow
from cloudshell.networking.brocade.runners.brocade_firmware_runner import BrocadeFirmwareRunner


class BrocadeFastIronFirmwareRunner(BrocadeFirmwareRunner):
    @property
    def load_firmware_flow(self):
        return BrocadeFastIronLoadFirmwareFlow(self.cli_handler, self._logger)
