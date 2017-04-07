from mock import patch
from threading import Thread

from cloudshell.devices.autoload.autoload_migration_helper import migrate_autoload_details
from cloudshell.shell.core.context import ResourceCommandContext, ResourceContextDetails, ReservationContextDetails
from driver import BrocadeFastIronShellDriver as ShellDriver


request = """{
  "driverRequest" : {
    "actions" : [{
      "connectionId" : "457238ad-4023-49cf-8943-219cb038c0dc",
      "connectionParams" : {
        "vlanId" : "45",
        "mode" : "Access",
        "vlanServiceAttributes" : [{
          "attributeName" : "QnQ",
          "attributeValue" : "True",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "CTag",
          "attributeValue" : "",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Isolation Level",
          "attributeValue" : "Shared",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Access Mode",
          "attributeValue" : "Access",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "VLAN ID",
          "attributeValue" : "876",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Virtual Network",
          "attributeValue" : "876",
          "type" : "vlanServiceAttribute"
        }, {
          "attributeName" : "Pool Name",
          "attributeValue" : "",
          "type" : "vlanServiceAttribute"
        }
        ],
        "type" : "setVlanParameter"
      },
      "connectorAttributes" : [],
      "actionId" : "457238ad-4023-49cf-8943-219cb038c0dc_4244579e-bf6f-4d14-84f9-32d9cacaf9d9",
      "actionTarget" : {
        "fullName" : "Router/Chassis 1/Module1/SubModule1/ge-0-0-6",
        "fullAddress" : "192.168.28.150/1/1/1/7",
        "type" : "actionTarget"
      },
      "customActionAttributes" : [],
      "type" : "setVlan"
    }
    ]
  }
}"""

SHELL_NAME = "Brocade FastIron Switch 2G" + "."
# SHELL_NAME = ""

# address = '10.254.12.19'
address = '10.254.11.69'
# address = '10.254.11.71'
user = 'root'
password = 'Password1'
# port = 1222
enable_password = 'Password2'
auth_key = 'h8WRxvHoWkmH8rLQz+Z/pg=='
api_port = 8029

context = ResourceCommandContext()
context.resource = ResourceContextDetails()
context.resource.name = 'Test FastIron'
context.resource.fullname = 'Test Brocade FastIron'
context.resource.family = 'CS_Switch'
context.reservation = ReservationContextDetails()
context.reservation.reservation_id = 'test_id'
context.resource.attributes = {}
context.resource.attributes['{}User'.format(SHELL_NAME)] = user
context.resource.attributes['{}Password'.format(SHELL_NAME)] = password
context.resource.attributes['{}host'.format(SHELL_NAME)] = address
context.resource.attributes['{}Enable Password'.format(SHELL_NAME)] = enable_password
# context.resource.attributes['Port'] = port
# context.resource.attributes['Backup Location'] = 'tftp://172.25.10.96/AireOS_test'
context.resource.attributes['{}Backup Location'.format(SHELL_NAME)] = 'tftp://10.254.12.168/08040a/Quali_Tests'
context.resource.address = address
# context.connectivity = ConnectivityContext()
# context.connectivity.admin_auth_token = auth_key
# context.connectivity.server_address = '10.5.1.2'
# context.connectivity.cloudshell_api_port = api_port
context.resource.attributes['{}SNMP Version'.format(SHELL_NAME)] = '2'
context.resource.attributes['{}SNMP Read Community'.format(SHELL_NAME)] = 'public'
context.resource.attributes['{}CLI Connection Type'.format(SHELL_NAME)] = 'telnet'
context.resource.attributes['{}Enable SNMP'.format(SHELL_NAME)] = 'False'
context.resource.attributes['{}Disable SNMP'.format(SHELL_NAME)] = 'False'
# context.resource.attributes['CLI Connection Type'] = 'telnet'
context.resource.attributes['{}Sessions Concurrency Limit'.format(SHELL_NAME)] = '1'


class MyThread(Thread):
    def __del__(self):
        print('{} deleted'.format(self.name))


if __name__ == '__main__':

    res = dict(context.resource.attributes)

    driver = ShellDriver()
    driver.initialize(context)

    with patch('driver.get_api') as get_api:
        api = type('api', (object,),
                   {'DecryptPassword': lambda self, pw: type('Password', (object,), {'Value': pw})()})()
        get_api.return_value = api
        # response = driver.get_inventory(context)
        # response = driver.health_check(context=context)
        # response = driver.run_custom_command(context=context, custom_command="show ver")
        # response = driver.save(context=context, folder_path="", configuration_type="running", vrf_management_name=None)
        # response = driver.save(context=context, folder_path="", configuration_type="startup", vrf_management_name=None)
        # response = driver.restore(context=context,
        #                           path="tftp://10.254.12.168/08040a/Quali_Tests/Test_FastIron-startup-070417-120005",
        #                           configuration_type="startup",
        #                           restore_method="override",
        #                           vrf_management_name=None)
        # response = driver.restore(context=context,
        #                           path="tftp://10.254.12.168/08040a/Quali_Tests/Test_FastIron-startup-070417-120005",
        #                           configuration_type="startup",
        #                           restore_method="append",
        #                           vrf_management_name=None)
        # response = driver.restore(context=context,
        #                           path="tftp://10.254.12.168/08040a/Quali_Tests/Test_FastIron-running-070417-115533",
        #                           configuration_type="running",
        #                           restore_method="override",
        #                           vrf_management_name=None)
        response = driver.restore(context=context,
                                  path="tftp://10.254.12.168/08040a/Quali_Tests/Test_FastIron-running-070417-115533",
                                  configuration_type="running",
                                  restore_method="append",
                                  vrf_management_name=None)
        print response
        print "*"*20, "FINISH", "*"*20



