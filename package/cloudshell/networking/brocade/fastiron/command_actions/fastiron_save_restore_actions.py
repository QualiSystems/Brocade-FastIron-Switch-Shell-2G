#!/usr/bin/python
# -*- coding: utf-8 -*-

import re

from cloudshell.cli.command_template.command_template_executor import CommandTemplateExecutor
from cloudshell.networking.brocade.command_templates import save_restore
from cloudshell.networking.brocade.fastiron.utils import buffer_readup


class FastIronSaveRestoreActions(object):
    BUFFER_READUP_TIMEOUT = 3
    BUFFER_READUP_RETRIES = 10

    def __init__(self, cli_service, logger):
        """ Save and Restore device configuration actions

        :param cli_service: default mode cli_service
        :type cli_service: CliService
        :param logger:
        :type logger: Logger
        :return:
        """

        self._cli_service = cli_service
        self._logger = logger

    def save(self, config, protocol, host, file_path, action_map=None, error_map=None):
        """ Save device configuration

        :param config: device configuration type. running-config or startup-config
        :param protocol: file transfer protocol. Example: tftp, ftp, scp ...
        :param host: remote server address
        :param file_path: full path to file on remote server
        :param action_map: actions will be taken during executing commands, i.e. handles yes/no prompts
        :param error_map: errors will be raised during executing commands, i.e. handles Invalid Commands errors
        :return:
        """

        output = CommandTemplateExecutor(self._cli_service, save_restore.SAVE,
                                         action_map=action_map,
                                         error_map=error_map).execute_command(config=config,
                                                                              scheme=protocol,
                                                                              host=host,
                                                                              file_path=file_path)

        output = buffer_readup(output=output,
                               cli_service=self._cli_service,
                               logger=self._logger,
                               max_retries=self.BUFFER_READUP_RETRIES,
                               retry_timeout=self.BUFFER_READUP_TIMEOUT)

        if not re.search(r"[Dd]one", output, re.DOTALL):
            matched = re.match(r"(Error.*)\n", output, re.DOTALL)
            if matched:
                error = matched.group()
            else:
                error = "Save device configuration failed"
            raise Exception(self.__class__.__name__, "Save configuration failed with error: {}".format(error))

    def restore(self, config, protocol, host, file_path, overwrite=False, action_map=None, error_map=None):
        """ Restore device configuration

        :param config: device configuration type. running-config or startup-config
        :param protocol: file transfer protocol. Example: tftp, ftp, scp ...
        :param host: remote server address
        :param file_path: full path to file on remote server
        :param overwrite: determines that device configuration can be reloaded without reboot
        :param action_map: actions will be taken during executing commands, i.e. handles yes/no prompts
        :param error_map: errors will be raised during executing commands, i.e. handles Invalid Commands errors
        :return:
        """

        if overwrite:
            output = CommandTemplateExecutor(self._cli_service, save_restore.RESTORE,
                                             action_map=action_map,
                                             error_map=error_map).execute_command(config=config,
                                                                                  scheme=protocol,
                                                                                  host=host,
                                                                                  file_path=file_path,
                                                                                  overwrite="")
        else:
            output = CommandTemplateExecutor(self._cli_service, save_restore.RESTORE,
                                             action_map=action_map,
                                             error_map=error_map).execute_command(config=config,
                                                                                  scheme=protocol,
                                                                                  host=host,
                                                                                  file_path=file_path)

        output = buffer_readup(output=output,
                               cli_service=self._cli_service,
                               logger=self._logger,
                               max_retries=self.BUFFER_READUP_RETRIES,
                               retry_timeout=self.BUFFER_READUP_TIMEOUT)

        if re.search(r"Invalid input", output, re.DOTALL):
            raise Exception(self.__class__.__name__, "Restore configuration failed. See logs for details")

        if not re.search(r"[Dd]one", output, re.DOTALL):
            matched = re.match(r"[Ee]rror.*", output, re.DOTALL)
            if matched:
                error = matched.group()
            else:
                error = "Restore device configuration failed"
            raise Exception(self.__class__.__name__, "Restore configuration failed with error: {}".format(error))
