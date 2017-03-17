#!/usr/bin/python
# -*- coding: utf-8 -*-

from cloudshell.devices.flows.action_flows import RemoveVlanFlow
from cloudshell.networking.brocade.command_actions.add_remove_vlan_actions import AddRemoveVlanActions
from cloudshell.networking.brocade.command_actions.iface_actions import IFaceActions


class BrocadeFastIronRemoveVlanFlow(RemoveVlanFlow):
    def __init__(self, cli_handler, logger):
        super(BrocadeFastIronRemoveVlanFlow, self).__init__(cli_handler, logger)

    def execute_flow(self, vlan_range, port_name, port_mode, action_map=None, error_map=None):
        """ Remove configuration of VLANs on multiple ports or port-channels

        :param vlan_range: VLAN or VLAN range
        :param port_name: full port name
        :param port_mode: mode which will be configured on port. Possible Values are trunk and access
        :param action_map:
        :param error_map:
        :return:
        """

        self._logger.info("Remove Vlan {} configuration started".format(vlan_range))

        if port_mode == "trunk":
            tag_type = "tagged"
        elif port_mode == "access":
            tag_type = "untagged"
        else:
            raise Exception(self.__class__.__name__,
                            "Unsupported port mode '{}'. Should be 'trunk' or 'access'".format(port_mode))

        with self._cli_handler.get_cli_service(self._cli_handler.config_mode) as config_session:
            iface_action = IFaceActions(config_session, self._logger)
            vlan_actions = AddRemoveVlanActions(config_session, self._logger)
            port_name = iface_action.get_port_name(port_name)

            try:
                if "-" in vlan_range:
                    start_vlan, end_vlan = vlan_range.split("-")
                    vlan_actions.configure_vlan_range(start_vlan=start_vlan, end_vlan=end_vlan)
                    vlan_actions.remove_vlan_from_interface(vlan=end_vlan, tag_type=tag_type, port_name=port_name)
                else:
                    vlan_actions.configure_vlan(vlan_range)
                    vlan_actions.remove_vlan_from_interface(vlan=vlan_range, tag_type=tag_type, port_name=port_name)
            except:
                raise Exception(self.__class__.__name__, "[FAIL] VLAN(s) {} removing failed".format(vlan_range))

        self._logger.info("VLAN(s) {} removing completed successfully".format(vlan_range))
        return "[ OK ] VLAN(s) {} removing completed successfully".format(vlan_range)
