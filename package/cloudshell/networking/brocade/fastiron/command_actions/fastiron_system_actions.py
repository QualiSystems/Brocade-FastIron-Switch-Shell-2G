#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.networking.brocade.command_actions.system_actions import SystemActions
from cloudshell.networking.brocade.fastiron.utils import buffer_readup


class FastIronSystemActions(SystemActions):
    BUFFER_READUP_TIMEOUT = 3
    BUFFER_READUP_RETRIES = 10

    def _buffer_readup(self, output):
        """ Read buffer to end of command execution if prompt returned immediately """

        return buffer_readup(output=output,
                             cli_service=self._cli_service,
                             logger=self._logger,
                             max_retries=self.BUFFER_READUP_RETRIES,
                             retry_timeout=self.BUFFER_READUP_TIMEOUT)
