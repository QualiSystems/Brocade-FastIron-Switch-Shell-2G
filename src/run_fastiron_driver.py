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

# address = '172.29.168.53'
address = '10.254.12.19'
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
context.resource.attributes['{}Backup Location'.format(SHELL_NAME)] = 'ftp://junos:junos@192.168.85.47'
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
        response = driver.run_custom_command(context=context, custom_command="show ver")
        # response = driver.send_custom_command(context=context, custom_command="show ver")

        print response
        print "*"*20, "FINISH", "*"*20



        # inventory = driver.get_inventory(context)
        # print(inventory)
        # print(driver.save(context, '', 'running'))
        # print(driver.save(context, '', 'startup'))
        # print(driver.save(context, '', ''))
        # print(driver.restore(context, 'ftp://junos:junos@192.168.85.47/TestAireOS-running-080816-191745', 'running', 'override'))
        # print(driver.restore(context, 'tftp://172.25.10.96/AireOS_test/TestAireOS-running-210716-160651', 'running', 'override'))
        # print(driver.ApplyConnectivityChanges(context, request))
        # Thread(target=driver.send_custom_command, args=(context, 'show interfaces')).start()
        # Thread(target=driver.update_firmware, args=(context, 'tftp://yar:pass@10.2.5.6:8435/test_path/test_file/323', '')).start()
        # time.sleep(1)
        # Thread(target=driver.get_inventory, args=(context,)).start()
        # Thread(target=driver.get_inventory, args=(context,)).start()
        # Thread(target=driver.get_inventory, args=(context,)).start()
        # Thread(target=driver.restore, args=(context, 'show interfaces', 'rer', 'rer')).start()
        # Thread(target=driver.get_inventory, args=(context,)).start()
        # Thread(target=driver.get_inventory, args=(context,)).start()

        # Thread(target=driver.save, args=(context, '', '')).start()
        # Thread(target=driver.send_custom_command, args=(context, 'fwrfwef fwe')).start()
        # Thread(target=driver.send_custom_command, args=(context, 'show interfaces')).start()
        # Thread(target=driver.send_custom_command, args=(context, 'help')).start()
        # Thread(target=driver.send_custom_command, args=(context, 'help')).start()
        # MyThread(target=driver.send_custom_command, args=(context, 'show run')).start()

        # MyThread(target=driver.send_custom_command, args=(context, 'show version')).start()
        # MyThread(target=driver.send_custom_command, args=(context, 'show run')).start()
        # MyThread(target=driver.send_custom_command, args=(context, 'show version')).start()
        # MyThread(target=driver.send_custom_command, args=(context, 'show run')).start()
        # MyThread(target=driver.send_custom_command, args=(context, 'show version')).start()

        # Thread(target=driver.send_custom_command, args=(context, 'help')).start()
        # Thread(target=driver.send_custom_command, args=(context, 'help')).start()
        # Thread(target=driver.send_custom_command, args=(context, 'help')).start()
        # [{<weakref at 0x7f08db4e7e68; to '_MainThread' at 0x7f08de6c72d0>: <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f08dc294a90>}, [<cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f08dc294a90>, <logging.Logger object at 0x7f08dc294910>, <cloudshell.cli.session.connection_manager.ConnectionManager object at 0x7f08dc294850>], (<cloudshell.networking.juniper.cli.juniper_cli_service.JuniperCliService object at 0x7f08dc280d10>, <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f08dc294a90>, <logging.Logger object at 0x7f08dc294910>, <cloudshell.cli.session.connection_manager.ConnectionManager object at 0x7f08dc294850>), (<cloudshell.networking.juniper.cli.juniper_cli_service.JuniperCliService object at 0x7f08dc280d10>, <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f08dc294a90>, <logging.Logger object at 0x7f08dc294910>, <cloudshell.cli.session.connection_manager.ConnectionManager object at 0x7f08dc294850>), <frame object at 0xe507e0>, <frame object at 0x1006280>]
        # [{<weakref at 0x7f1a3ceb8aa0; to '_MainThread' at 0x7f1a400982d0>: <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f1a3dc65a50>}, <frame object at 0x2803ea0>, {'logger': <logging.Logger object at 0x7f1a3dc658d0>, 'session': <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f1a3dc65a50>}, <frame object at 0x27147a0>, {'logger': <logging.Logger object at 0x7f1a3dc658d0>, 'session': <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f1a3dc65a50>, 'expected_map': None}, <frame object at 0x2874d80>, <cell at 0x7f1a3cb74868: ReturnToPoolProxy object at 0x7f1a3dc65a50>, [<cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f1a3dc65a50>, <logging.Logger object at 0x7f1a3dc658d0>, <cloudshell.cli.session.connection_manager.ConnectionManager object at 0x7f1a3dc65810>], (<cloudshell.networking.juniper.cli.juniper_cli_service.JuniperCliService object at 0x7f1a3dc52cd0>, <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f1a3dc65a50>, <logging.Logger object at 0x7f1a3dc658d0>, <cloudshell.cli.session.connection_manager.ConnectionManager object at 0x7f1a3dc65810>), (<cloudshell.networking.juniper.cli.juniper_cli_service.JuniperCliService object at 0x7f1a3dc52cd0>, <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f1a3dc65a50>, <logging.Logger object at 0x7f1a3dc658d0>, <cloudshell.cli.session.connection_manager.ConnectionManager object at 0x7f1a3dc65810>), <frame object at 0x28040f0>, <frame object at 0x28732c0>, {'logger': <logging.Logger object at 0x7f1a3dc658d0>, 'session': <cloudshell.cli.session.session_proxy.ReturnToPoolProxy object at 0x7f1a3dc65a50>}]
