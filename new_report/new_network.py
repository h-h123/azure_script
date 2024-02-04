import csv
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
import os

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


#######################################################################################################

def network_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
    fieldnames = ["Date Time"]
    with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        writer.writerow([datetime_now])
        # First sentences
        for sentence in sentences1:
            writer.writerow([sentence])
        # Second Sentences
        for sentence in sentences2:
            writer.writerow([sentence])
        
        writer.writerow(["-------------------------------------------------------------------------------------------------------------------------------------------------------------------"])

#######################################################################################################

def network_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3):
    fieldnames = ["Date Time"]
    with open(csv_file_path2, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        writer.writerow([datetime_now])
        # First sentences
        for sentence in sentences1:
            writer.writerow([sentence])
        # Second Sentences
        for sentence in sentences3:
            writer.writerow([sentence])
        
        writer.writerow(["-------------------------------------------------------------------------------------------------------------------------------------------------------------------"])



#######################################################################################################

def new_Report_network_sentences1and2_save_to_csv_for_html_report(csv_file_path3, datetime_now, details_dict):
    fieldnames = ["Date Time", "Subscription Name", "Subscription ID", "Total NSG checks found in the subscription", "Vulnerable NSGs", "Total Network Watcher found in the subscription", "Network Watchers not Provisioned", "Details"]
    
    with open(csv_file_path3, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if file.tell() == 0:
            writer.writeheader()

        # Use details_dict directly
        data = {
            "Date Time": datetime_now,
            "Subscription Name": details_dict.get("Subscription Name", ""),
            "Subscription ID": details_dict.get("Subscription ID", ""),
            "Total NSG checks found in the subscription": details_dict.get("Total NSG checks found in the subscription", ""),
            "Vulnerable NSGs": details_dict.get("Vulnerable NSGs", ""),
            "Total Network Watcher found in the subscription": details_dict.get("Total Network Watcher found in the subscription", ""),
            "Network Watchers not Provisioned": details_dict.get("Network Watchers not Provisioned", ""),
            "Details": ', \n'.join(details_dict.get("Details", []))  # Join the list of sentences into a string
        }

        writer.writerow(data)



#######################################################################################################


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
    detected_nsg_names = []
    detected_nsg_resource_groups = []
    detected_network_watcher_names = []
    detected_network_watcher_resource_groups = []
    csv_file_path = "azure_HTML_report2.csv"
    datetime_now = datetime.now()
    sentences1 = [] # Details of count
    sentences2 = [] # All details for HTML report
    csv_file_path2 = "Azure_Report.csv"
    sentences3 = [] # Specific detail for users to see vulnerabilities only
    csv_file_path3 = 'New_report.csv'
    # Details dictionary for the current subscription
    details_dict = {
    "Subscription Name": "",
    "Subscription ID": "",
    "Total NSG checks found in the subscription": 0,
    "Vulnerable NSGs": 0,
    "Total Network Watcher found in the subscription": 0,
    "Network Watchers not Provisioned": 0,
    "Details": []  # Details will be a list of sentences
    }


    try:
        print(f"------Detecting Vulnerabilities in Networking------")
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())


        for subscription_id in subscription_ids:
            network_client = NetworkManagementClient(credential, subscription_id)    
            resource_client = ResourceManagementClient(credential, subscription_id)
            resource_groups = resource_client.resource_groups.list()

            for resource_group in resource_groups:
                # print(f"\n{'-'*10} {resource_group.name} Resource Group {'-'*10}")
                # Check for NSG vulnerabilities
                try:
                    print(f"\nChecking for NSG Vulnerabilities in the Resource Group: {resource_group.name} ...")

                    # Get NSGs in the resource group
                    nsgs = network_client.network_security_groups.list(resource_group_name=resource_group.name)

                    for nsg in nsgs:
                        #print(f"\nChecking NSG Vulnerabilities in '{resource_group.name}' Resource Group:\t")
                        sentences2.append(f"\nChecking NSG Vulnerabilities in '{resource_group.name}' Resource Group:\t")
                        sentences3.append(f"\nChecking NSG Vulnerabilities in '{resource_group.name}' Resource Group:\t")
                        details_dict["Details"].append(f"\nResource_Group:{resource_group.name}")


                        if not nsg:
                            #print(f"No NSGs found in the '{resource_group.name}' resource group.")
                            sentences2.append(f"No NSGs found in the '{resource_group.name}' resource group.")
                        #    sentences3.append(f"No NSGs found in the '{resource_group.name}' resource group.")
                            # details_dict["Details"].append(f"No NSGs found in the '{resource_group.name}' resource group.")

                        else:
                            total_nsg_checks += 1
                            #print(f"\tNSG named '{nsg.name}'found in the '{resource_group.name}' resource group.")
                            sentences2.append(f"\tNSG named '{nsg.name}'found in the '{resource_group.name}' resource group.")
                        #    sentences3.append(f"\tNSG named '{nsg.name}'found in the '{resource_group.name}' resource group.")
                            # details_dict["Details"].append(f"NSG named '{nsg.name}'found in the '{resource_group.name}' resource group.")

                        allowed_protocols = {'ssh', 'http', 'rdp', 'https'}
                        allowed_rules = [find_security_rule_by_name(nsg, protocol) for protocol in allowed_protocols]
                        allowed_rules = [rule for rule in allowed_rules if rule and is_access_allow(rule)]

                        # Check if there are more than one allowed rules
                        if len(allowed_rules) > 1:
                            print(f"The NSG '{nsg.name}'in the resource group '{resource_group.name}'")
                            print(f"\tVulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed (Consider Restricting)")
                            sentences2.append(f"\tVulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed (Consider Restricting)")
                            sentences3.append(f"\tVulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed (Consider Restricting)")
                            
                            details_dict["Details"].append(f"Vulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed in the NSG '{nsg.name}'in the resource group '{resource_group.name}'(Consider Restricting)")

                            print(f"\tAllowed Protocols:")
                            sentences2.append(f"\tAllowed Protocols:")
                            sentences3.append(f"\tAllowed Protocols:")
                            details_dict["Details"].append(f"\tAllowed Protocols:")

                            for rule in allowed_rules:
                                print(f"\t - {rule.name}")
                                sentences2.append(f"\t - {rule.name}")
                                sentences3.append(f"\t - {rule.name}")
                                details_dict["Details"].append(f"\t - {rule.name}")
                            detected_nsg_count += 1
                        else:
                            # Check individual vulnerabilities
                            ssh_detected = check_ssh_vulnerability(nsg)
                            udp_detected = check_udp_vulnerability(nsg)
                            rdp_detected = check_rdp_vulnerability(nsg)

                            if ssh_detected:
                                detected_nsg_count += 1
                                print(f"The NSG '{nsg.name}'in the resource group '{resource_group.name}'")
                                print(f"\tWarning: Inbound SSH access is allowed.")
                                sentences2.append(f"\tWarning: Inbound SSH access is allowed.")
                                sentences3.append(f"\tWarning: Inbound SSH access is allowed.")
                                details_dict["Details"].append(f"Warning: Inbound SSH access is allowed for the NSG '{nsg.name}'in the resource group '{resource_group.name}'.")

                            if udp_detected:
                                detected_nsg_count += 1
                                print(f"The NSG '{nsg.name}'in the resource group '{resource_group.name}'")
                                print(f"\tWarning: Inbound UDP access is allowed.")
                                sentences2.append(f"\tWarning: Inbound UDP access is allowed.")
                                sentences3.append(f"\tWarning: Inbound UDP access is allowed.")
                                details_dict["Details"].append(f"Warning: Inbound UDP access is allowed for the NSG '{nsg.name}'in the resource group '{resource_group.name}'.")


                            if rdp_detected:
                                detected_nsg_count += 1
                                print(f"The NSG '{nsg.name}'in the resource group '{resource_group.name}'")
                                print(f"\tWarning: Inbound RDP access is allowed.")
                                sentences2.append(f"\tWarning: Inbound RDP access is allowed.")
                                sentences3.append(f"\tWarning: Inbound RDP access is allowed.")
                                details_dict["Details"].append(f"Warning: Inbound RDP access is allowed for the NSG '{nsg.name}'in the resource group '{resource_group.name}'.")




                        # Recording information for CSV
                        detected_nsg_names.append(nsg.name)
                        detected_nsg_resource_groups.append(resource_group.name)


                except Exception as e:
                    print(f'Error checking NSG vulnerabilities: {e}')
                    sentences2.append(f'Error checking NSG vulnerabilities: {e}')
                    sentences3.append(f'Error checking NSG vulnerabilities: {e}')
                    details_dict["Details"].append(f'Error checking NSG vulnerabilities: {e}')


            ##############################################################

                # Check Network Watchers
                try:
                    print(f"\nChecking for Network Watchers in the Resource Group: {resource_group.name}...")

                    # Get Network Watchers in the resource group
                    network_watchers = network_client.network_watchers.list(resource_group_name=resource_group.name)

                    for network_watcher in network_watchers:
                        #print(f"\nChecking Network Watchers in '{resource_group.name}' Resource Group:")
                        sentences2.append(f"\nChecking Network Watchers in '{resource_group.name}' Resource Group:")
                        sentences3.append(f"\nChecking Network Watchers in '{resource_group.name}' Resource Group:")
                        details_dict["Details"].append(f"\nResource_Group:{resource_group.name}")

                        if not network_watcher:
                            print(f"\tVulnerability: No Network Watchers found in the '{resource_group.name}' resource group. Network Watcher is disabled.")
                            sentences2.append(f"\t Vulnerability: No Network Watchers found in the '{resource_group.name}' resource group. Network Watcher is disabled.")
                            sentences3.append(f"\t Vulnerability: No Network Watchers found in the '{resource_group.name}' resource group. Network Watcher is disabled.")
                            details_dict["Details"].append(f"Vulnerability: No Network Watchers found in the '{resource_group.name}' resource group. Network Watcher is disabled.")
                        else:
                            total_network_watcher_checks += 1
                            #print(f"\t1. Network Watcher named '{network_watcher.name}' is Enabled in the '{resource_group.name}' resource group.")
                            sentences2.append(f"\t Network Watcher named '{network_watcher.name}' is Enabled in the '{resource_group.name}' resource group.")
                            details_dict["Details"].append(f"Network Watcher named '{network_watcher.name}' is Enabled in the '{resource_group.name}' resource group.")

                        # Check if Network Watcher is  provisioned successfully
                        if network_watcher.provisioning_state.lower() == 'succeeded':
                            #print(f"\t2. Network Watcher named '{network_watcher.name}' is provisioned successfully.")
                            sentences2.append(f"\t Network Watcher named '{network_watcher.name}' is provisioned successfully.")
                            details_dict["Details"].append(f"Network Watcher named '{network_watcher.name}' is provisioned successfully.")
                        else:
                            detected_network_watcher_count += 1
                            print(f"\tVulnerability: Network Watcher named '{network_watcher.name}' provisioning is not in a successful state.")
                            sentences2.append(f"\t Vulnerability: Network Watcher named '{network_watcher.name}' provisioning is not in a successful state.")
                            sentences3.append(f"\t Vulnerability: Network Watcher named '{network_watcher.name}' provisioning is not in a successful state.")
                            details_dict["Details"].append(f"\tVulnerability: Network Watcher named '{network_watcher.name}' provisioning is not in a successful state.")

                        if network_watcher and network_watcher.provisioning_state.lower() == 'succeeded':
                            sentences2.append(f"\tNo vulnerability Found !")
                            sentences3.append(f"\tNo vulnerability Found !")
                            # details_dict["Details"].append(f"\tNo vulnerability Found !")

                        # Recording information for CSV
                        detected_network_watcher_names.append(network_watcher.name)
                        detected_network_watcher_resource_groups.append(resource_group.name)
                    

                except Exception as e:
                    print(f'Error checking network watchers: {e}')
                    sentences2.append(f'Error checking network watchers: {e}')
                    sentences3.append(f'Error checking network watchers: {e}')
                    details_dict["Details"].append(f'Error checking network watchers: {e}')

            # Printing Information
            for sub in subscriptions:
                if sub.subscription_id == subscription_id:
                    print(f"\nSubscription Name: {sub.display_name}")
                    sentences1.append(f"\nSubscription Name: {sub.display_name}")
                    sentences1.append(f"Subscription ID: {sub.subscription_id}")

                    print(f"\tTotal NSG checks found in the subscription: {total_nsg_checks}")
                    sentences1.append(f"\nTotal NSG checks found in the subscription: {total_nsg_checks}")

                    print(f"\tVulnerable NSGs: {detected_nsg_count}")
                    sentences1.append(f"Vulnerable NSGs: {detected_nsg_count}")

                    print(f"\tTotal Network Watcher found in the subscription : {total_network_watcher_checks}")
                    sentences1.append(f"Total Network Watcher found in the subscription : {total_network_watcher_checks}")
                    
                    print(f"\tNetwork Watchers not Provisioned: {detected_network_watcher_count}")
                    sentences1.append(f"Network Watchers not Provisioned: {detected_network_watcher_count}")
                    
                    print(f"-" * 160)
                    #print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")
                    
                    details_dict["Subscription Name"] = sub.display_name
                    details_dict["Subscription ID"] = sub.subscription_id
                    details_dict["Total NSG checks found in the subscription"] = total_nsg_checks
                    details_dict["Vulnerable NSGs"] = detected_nsg_count
                    details_dict["Total Network Watcher found in the subscription"] = total_network_watcher_checks
                    details_dict["Network Watchers not Provisioned"] = detected_network_watcher_count

                #Call the save to csv function for html report
                network_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
                network_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)
                new_Report_network_sentences1and2_save_to_csv_for_html_report(csv_file_path3, datetime_now, details_dict)

    except Exception as e:
        print(f'Error in checking network resources: {e}')
        sentences2.append(f'Error in checking network resources: {e}')
        sentences3.append(f'Error in checking network resources: {e}')
        details_dict["Details"].append(f'Error in checking network resources: {e}')

if __name__ == '__main__':
    subscriptions = get_subscriptions()
    subscription_input = input("\nEnter the subscription ID(s) you want to check (comma-separated) or type 'all' for all subscriptions: ")

    if subscription_input.lower() == 'all':
        subscription_ids = [sub.subscription_id for sub in subscriptions]
    else:
        subscription_ids = [sub.strip() for sub in subscription_input.split(',')]

    check_network(subscription_ids)
