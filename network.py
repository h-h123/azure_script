import csv
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient


def get_subscriptions():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())

        print("Available Subscriptions:")
        for sub in subscriptions:
            print(f"Subscription Name: {sub.display_name}, Subscription ID: {sub.subscription_id}")

        return subscriptions
    except Exception as e:
        print(f"Error retrieving subscriptions: {e}")
        raise

########################################################################################################


def check_ssh_vulnerability(nsg):
    rule = find_security_rule_by_name(nsg, 'ssh')

    if rule and (is_inbound_access_allow(rule) or is_address_prefix_star(rule)):
        #print("Vulnerability: Inbound SSH Access Allowed or Vulnerable Address Prefix")
        return True
    return False

def check_udp_vulnerability(nsg):
    rule = find_security_rule_by_name(nsg, 'udp')

    if rule and (is_inbound_access_allow(rule) or is_address_prefix_star(rule)):
        #print("Vulnerability: Inbound UDP Access Allowed or Vulnerable Address Prefix")
        return True
    return False

def check_rdp_vulnerability(nsg):
    rule = find_security_rule_by_name(nsg, 'rdp')

    if rule and (is_inbound_access_allow(rule) or is_address_prefix_star(rule)):
        #print("Vulnerability: Inbound RDP Access Allowed or Vulnerable Address Prefix")
        return True
    return False

def find_security_rule_by_name(nsg, rule_name):
    return next((rule for rule in nsg.security_rules if rule.name.lower() == rule_name), None)

def is_inbound_access_allow(rule):
    return rule and rule.access.lower() == 'allow' and rule.direction.lower() == 'inbound'

def is_access_allow(rule):
    return rule and rule.access.lower() == 'allow'

def is_address_prefix_star(rule):
    return rule and (rule.source_address_prefix == '*' or rule.destination_address_prefix == '*')


######################################################################################################


def check_network(subscription_ids):
    total_nsg_checks = 0
    detected_nsg_count = 0
    total_network_watcher_checks = 0
    detected_network_watcher_count = 0  #network watchers which are not provisioned to succeed

    try:
        credential = DefaultAzureCredential()

        for subscription_id in subscription_ids:
            network_client = NetworkManagementClient(credential, subscription_id)    
            resource_client = ResourceManagementClient(credential, subscription_id)
            resource_groups = resource_client.resource_groups.list()

            for resource_group in resource_groups:
                # print(f"\n{'-'*10} {resource_group.name} Resource Group {'-'*10}")
                # Check for NSG vulnerabilities
                try:
                    # print(f"\nChecking NSG Vulnerabilities in {resource_group.name} Resource Group:")

                    # Get NSGs in the resource group
                    nsgs = network_client.network_security_groups.list(resource_group_name=resource_group.name)

                    for nsg in nsgs:
                        print(f"\nChecking NSG Vulnerabilities in {resource_group.name} Resource Group:\t")

                        if not nsg:
                            print(f"No NSGs found in the {resource_group.name} resource group.")
                        else:
                            total_nsg_checks += 1
                            print(f"\tNSG named {nsg.name} found in the {resource_group.name} resource group.")

                        allowed_protocols = {'ssh', 'http', 'rdp', 'https'}
                        allowed_rules = [find_security_rule_by_name(nsg, protocol) for protocol in allowed_protocols]
                        allowed_rules = [rule for rule in allowed_rules if rule and is_access_allow(rule)]

                        # Check if there are more than one allowed rules
                        if len(allowed_rules) > 1:
                            print("\tDetected Vulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed (Consider Restricting)")
                            print("\tAllowed Protocols:")
                            for rule in allowed_rules:
                                print(f"\t - {rule.name}")
                            detected_nsg_count += 1
                        else:
                            # Check individual vulnerabilities
                            ssh_detected = check_ssh_vulnerability(nsg)
                            udp_detected = check_udp_vulnerability(nsg)
                            rdp_detected = check_rdp_vulnerability(nsg)

                            if ssh_detected:
                                detected_nsg_count += 1
                                print("\tDetected vulnerability: Inbound SSH access is allowed or there is a vulnerable address prefix.")

                            if udp_detected:
                                detected_nsg_count += 1
                                print("\tDetected vulnerability: Inbound UDP access is allowed or there is a vulnerable address prefix.")

                            if rdp_detected:
                                detected_nsg_count += 1
                                print("\tDetected vulnerability: Inbound RDP access is allowed or there is a vulnerable address prefix.")


                except Exception as e:
                    print(f'Error checking NSG vulnerabilities: {e}')

            ##############################################################

                # Check Network Watchers
                try:
                    # print(f"\nChecking Network Watchers in {resource_group.name} Resource Group:")

                    # Get Network Watchers in the resource group
                    network_watchers = network_client.network_watchers.list(resource_group_name=resource_group.name)

                    for network_watcher in network_watchers:
                        print(f"\nChecking Network Watchers in {resource_group.name} Resource Group:")

                        if not network_watcher:
                            print(f"\tNo Network Watchers found in the {resource_group.name} resource group. Network Watcher is disabled.")
                        else:
                            total_network_watcher_checks += 1
                            print(f"\t{network_watcher.name} named Network Watcher is Enabled in the {resource_group.name} resource group.")

                        # Check if Network Watcher is  provisioned successfully
                        if network_watcher.provisioning_state.lower() == 'succeeded':
                            print(f"\tNetwork Watcher named {network_watcher.name} is provisioned successfully.")
                        else:
                            detected_network_watcher_count += 1
                            print(f"\tNetwork Watcher named {network_watcher.name} provisioning is not in a successful state.")

                except Exception as e:
                    print(f'Error checking network watchers: {e}')

    except Exception as e:
        print(f'Error in checking network resources: {e}')

    print("-------------------------------------------------------------------------------------------")
    print(f"\nTotal NSG checks found in the subscription: {total_nsg_checks}")
    print(f"Vulnerable NSGs: {detected_nsg_count}")
    print(f"Total Network Watcher found in the subscription : {total_network_watcher_checks}")
    print(f"Network Watchers not Provisioned: {detected_network_watcher_count}")


if __name__ == '__main__':
    subscriptions = get_subscriptions()
    subscription_input = input("\nEnter the subscription ID(s) you want to check (comma-separated) or type 'all' for all subscriptions: ")

    if subscription_input.lower() == 'all':
        subscription_ids = [sub.subscription_id for sub in subscriptions]
    else:
        subscription_ids = [sub.strip() for sub in subscription_input.split(',')]

    check_network(subscription_ids)
