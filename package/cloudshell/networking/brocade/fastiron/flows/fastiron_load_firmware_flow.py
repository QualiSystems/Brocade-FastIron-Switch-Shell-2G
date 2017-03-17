#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.networking.brocade.flows.brocade_load_firmware_flow import BrocadeLoadFirmwareFlow
from cloudshell.networking.brocade.fastiron.command_actions.fastiron_system_actions import FastIronSystemActions


class BrocadeFastIronLoadFirmwareFlow(BrocadeLoadFirmwareFlow):
    SYSTEM_ACTIONS_CLASS = FastIronSystemActions
