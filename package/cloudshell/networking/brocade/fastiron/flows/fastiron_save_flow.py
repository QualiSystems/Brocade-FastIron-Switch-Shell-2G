#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.networking.brocade.fastiron.command_actions.fastiron_save_restore_actions import \
    FastIronSaveRestoreActions
from cloudshell.networking.brocade.flows.brocade_save_flow import BrocadeSaveFlow


class BrocadeFastIronSaveFlow(BrocadeSaveFlow):
    SAVE_RESTORE_ACTIONS_CLASS = FastIronSaveRestoreActions
