import csv
import os
from datetime import datetime
from collections import defaultdict
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.keyvault.secrets import SecretClient


# Code :  1. VM code
#         2. Network Code
#         3. Web App Code
#         4. Storage Account Code
#         5. Key Vault Code
#################################################################################################
#################################################################################################
#################################################################################################





def get_subscriptions():
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    subscriptions = list(subscription_client.subscriptions.list())

    print("Available Subscriptions:")
    for sub in subscriptions:
        print(f"Subscription Name: {sub.display_name}, Subscription ID: {sub.subscription_id}")







#################################################################################################
#################################################################################################
#################################################################################################







# VM Code:
try:
    
    #######################################################################################################

    def vm_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
        fieldnames = ["Date Time"]
        with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["------Detecting Vulnerabilities in Virtual Machines------\n"])
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

    def vm_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3):
        fieldnames = ["Date Time"]
        with open(csv_file_path2, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["------Detecting Vulnerabilities in Virtual Machines------\n"])
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




    def check_unsecured_vm_instances(subscription_ids):
        print(f"\n\n------Detecting Vulnerabilities in Virtual Machines------")
        total_vm_checked_count = 0
        detected_vm_count = 0
        total_disk_checked_count = 0
        detected_disk_count = 0
        csv_file_path = "azure_HTML_report.csv"
        datetime_now = datetime.now()
        sentences1 = [] # Details of counts
        sentences2 = [] # All details for HTML report
        csv_file_path2 = "Azure_Report.csv"
        sentences3 = [] # Specific detail for users to see vulnerabilities only in CSV file
        

        try:
            credential = DefaultAzureCredential()
            subscription_client = SubscriptionClient(credential)
            subscriptions = list(subscription_client.subscriptions.list())

            for subscription_id in subscription_ids:
                compute_client = ComputeManagementClient(credential, subscription_id)
                network_client = NetworkManagementClient(credential, subscription_id)

                vms = compute_client.virtual_machines.list_all()


                insecure_vms = []
                #vm_details = defaultdict(list)

                for vm in vms:
                    resource_group_of_vm = vm.id.split("/")[4]
                    print(f"\nChecking for VM '{vm.name}' in the Resource group '{resource_group_of_vm}'...")
                    sentences2.append(f"\nChecking for VM '{vm.name}' in the Resource group '{resource_group_of_vm}'...")
                    sentences3.append(f"\nChecking for VM '{vm.name}' in the Resource group '{resource_group_of_vm}'...")

                    total_vm_checked_count += 1

                    nics = [nic for nic in network_client.network_interfaces.list(resource_group_name=vm.id.split("/")[4]) if nic.virtual_machine.id.split('/')[-1] == vm.id.split("/")[8]]
                    
                    # Initialize variables to track conditions
                    has_public_ip_and_open_to_all = False
                    overly_permissive_nsg_rule = False
                    misconfigured_security_rule = False
                    unsecured = False

                    for nic in nics:
                        ip_configurations = nic.ip_configurations
                        
                        for ip_config in ip_configurations:
                            if ip_config.public_ip_address is not None:
                                has_public_ip_and_open_to_all = True

                        nsg_id = nic.network_security_group.id.split('/')[-1]
                        nsg = network_client.network_security_groups.get(
                            resource_group_name=vm.id.split("/")[4],
                            network_security_group_name=nsg_id
                        )

                        # Check for overly permissive NSG rules
                        if any(rule.source_address_prefix == '*' and rule.destination_address_prefix == '*' for rule in nsg.security_rules):
                            overly_permissive_nsg_rule = True

                        # Check for misconfigured security rules
                        for rule in nsg.security_rules:
                            if rule.protocol in ['TCP', 'UDP'] and rule.access == 'Allow' and rule.destination_port_range in ['3389', '22']:
                                misconfigured_security_rule = True

                    # Check if all conditions are met before flagging the VM as unsecured
                    if has_public_ip_and_open_to_all and overly_permissive_nsg_rule and misconfigured_security_rule:
                        detected_vm_count += 1
                        insecure_vms.append(vm.name)
                        unsecured = True
                        print(f"\t> VM '{vm.name}' is Unsecured (Reason - It has overly-permissive inbound rules for management ports in Network Security Group of VM and Open remote management ports are exposing VM to a high level of risk from Internet-based attack.)")
                        sentences2.append(f"\t> VM '{vm.name}' is Unsecured (Reason - It has overly-permissive inbound rules for management ports in Network Security Group of VM and Open remote management ports are exposing VM to a high level of risk from Internet-based attack.)")
                        sentences2.append(f"\tRemediation - Enable just-in-time access control to protect your VM from internet-based brute-force attacks.")
                        sentences3.append(f"\t> VM '{vm.name}' is Unsecured (Reason - It has overly-permissive inbound rules for management ports in Network Security Group of VM and Open remote management ports are exposing VM to a high level of risk from Internet-based attack.)")


            ####################################################################################


                    #Information about Disk in the subscription
                    disks_list = compute_client.disks.list_by_resource_group(resource_group_name=vm.id.split("/")[4])
                    for disk in disks_list:
                        total_disk_checked_count += 1
                        RG_of_disk = disk.id.split("/")[4]
                        # print(f"\nVM : ",vm.name)
                        # print(f"Disk Name: {disk.name}")
                        print(f"\nChecking for Disk '{disk.name}' in RG '{RG_of_disk}'...")
                        sentences2.append(f"\nChecking for Disk '{disk.name}' in RG - {RG_of_disk}...")
                        sentences3.append(f"\nChecking for Disk '{disk.name}' in RG - {RG_of_disk}...")


                        # check_disk_vulnerability_warning_scenarios(disk)

                        # Disk is attached to Virtual Machine or not 
                        disk_attached_vm_name = disk.managed_by.split("/")[8]
                        RG_of_disk = disk.id.split("/")[4]
                        #print(f"\nDisk {disk.name} is attached to VM: {disk_attached_vm_name} in resource group: {RG_of_disk}")
                        if disk.disk_state == 'Attached':
                            #print(f"\t> The disk '{disk.name}' is attached to the virtual machine '{disk_attached_vm_name}'.")
                            sentences2.append(f"\t> The disk '{disk.name}' is attached to the virtual machine '{disk_attached_vm_name}'.")

                        else:
                            print(f"\t> Warning: The Disk {disk.name} in the RG '{RG_of_disk}'is not attached to any VM.")
                            sentences2.append(f"\t> Warning: The Disk {disk.name} in the RG '{RG_of_disk}' is not attached to any VM.")
                            sentences3.append(f"\t> Warning: The Disk {disk.name} in the RG '{RG_of_disk}' is not attached to any VM.")

                        # Data Access Auth Mode
                        if disk.data_access_auth_mode is None:
                            print(f"\t> Vulnerability: Data Access Authentication Mode is configured with weak or no authentication for the disk '{disk.name}'.")
                            #print(f"\tRisk: Unauthorized users may gain access to sensitive disk data, leading to potential data breaches.")
                            #print(f"\tRecommendation: Ensure strong authentication methods, such as Azure AD/ Entra ID credentials, are enforced.")
                            sentences2.append(f"\t> Vulnerability: Data Access Authentication Mode is configured with weak or no authentication for the disk '{disk.name}'.")
                            sentences2.append(f"\tRisk: Unauthorized users may gain access to sensitive disk data, leading to potential data breaches.")
                            sentences2.append(f"\tRecommendation: Ensure strong authentication methods, such as Azure AD/ Entra ID credentials, are enforced.")
                            sentences3.append(f"\t> Vulnerability: Data Access Authentication Mode is configured with weak or no authentication for the disk '{disk.name}'.")
                        else:
                            #print(f"\t> Data Access Authentication Mode is configured (Secure) for disk '{disk.name}'")
                            sentences2.append(f"\t> Data Access Authentication Mode is configured (Secure) for disk '{disk.name}'")


                        # Encryption Settings
                        if not disk.encryption:
                            print(f"\t> Vulnerability: Encryption settings are not configured for the disk '{disk.name}'.")
                            sentences2.append(f"\t> Vulnerability: Encryption settings are not configured for the disk '{disk.name}'.")
                            sentences3.append(f"\t> Vulnerability: Encryption settings are not configured for the disk '{disk.name}'.")
                        else:
                            #print(f"\t> Encryption settings for the disk '{disk.name}' are configured.")
                            sentences2.append(f"\t> Encryption settings for the disk '{disk.name}' are configured.")


                        # Optimized for Frequent Attach
                        if disk.optimized_for_frequent_attach and 'sensitive_data' in disk.tags:
                            print(f"\t> Warning: Disk '{disk.name}' is optimized for frequent attachment, but it contains sensitive data.")
                            #print(f"\tRisk: Frequent attaching may expose the disk to unintended access, increasing the risk of data compromise.")
                            #print(f"\tRecommendation: Assess the need for frequent attachment and optimize performance accordingly. Consider encryption for sensitive data.")
                            sentences2.append(f"\t> Warning: Disk '{disk.name}' is optimized for frequent attachment, but it contains sensitive data.")
                            sentences2.append(f"\tRisk: Frequent attaching may expose the disk to unintended access, increasing the risk of data compromise.")
                            sentences2.append(f"\tRecommendation: Assess the need for frequent attachment and optimize performance accordingly. Consider encryption for sensitive data.")
                            sentences3.append(f"\t> Warning: Disk '{disk.name}' is optimized for frequent attachment, but it contains sensitive data.")
                        else:
                            #print(f"\t> The disk '{disk.name}' is not configured for frequent attachment optimization or does not contain sensitive data.")
                            #print(f"\tExplanation: Frequent attachment optimization is not applicable, and the disk does not pose a risk of unintended access or data compromise.")
                            sentences2.append(f"\t> The disk '{disk.name}' is not configured for frequent attachment optimization or does not contain sensitive data.")
                            sentences2.append(f"\tExplanation: Frequent attachment optimization is not applicable, and the disk does not pose a risk of unintended access or data compromise.")
                            

                        # Bursting Enabled Time
                        if disk.bursting_enabled_time and disk.bursting_enabled_time.startswith("peak_hours"):
                            print(f"\t> Warning: Bursting is currently enabled during peak operational hours for the disk '{disk.name}'.")
                            #print(f"\tRisk: Bursting might consume additional resources, impacting overall system performance during peak hours.")
                            #print(f"\tRecommendation: Schedule bursting during non-peak hours and monitor resource utilization to avoid performance degradation.")
                            sentences2.append(f"\t> Warning: Bursting is currently enabled during peak operational hours for the disk '{disk.name}'.")
                            sentences2.append(f"\tRisk: Bursting might consume additional resources, impacting overall system performance during peak hours.")
                            sentences2.append(f"\tRecommendation: Schedule bursting during non-peak hours and monitor resource utilization to avoid performance degradation.")
                            sentences3.append(f"\t> Warning: Bursting is currently enabled during peak operational hours for the disk '{disk.name}'.")
                        else:
                            #print(f"\t> Bursting in the disk '{disk.name}' is either not enabled or not configured for peak operational hours.")
                            sentences2.append(f"\t> Bursting in the disk '{disk.name}' is either not enabled or not configured for peak operational hours.")



                        # Check if all conditions are met before flagging the Disk as unsecured
                        if  not disk.encryption or disk.data_access_auth_mode is None:
                            detected_disk_count += 1
                            #print(f"\n\tDisk '{disk.name}' is Vulnerable (Reason - Encryption settings are not configured & Data Access Authentication Mode is configured with weak or no authentication)")
                            sentences2.append(f"\n\t* Disk '{disk.name}' is Vulnerable (Reason - Encryption settings are not configured & Data Access Authentication Mode is configured with weak or no authentication)")
                            #sentences3.append(f"\n\tDisk '{disk.name}' is Vulnerable (Reason - Encryption settings are not configured & Data Access Authentication Mode is configured with weak or no authentication)")


                # Printing Information
                for sub in subscriptions:
                    if sub.subscription_id == subscription_id:
                        print(f"\nSubscription Name: {sub.display_name}")
                        sentences1.append(f"\nSubscription Name: {sub.display_name}")
                        sentences1.append(f"Subscription ID: {sub.subscription_id}")

                        print(f"\tTotal VMs checked:", total_vm_checked_count)
                        sentences1.append(f"\nTotal VMs checked: {total_vm_checked_count}")

                        print(f"\tDetected unsecured VMs:", len(insecure_vms))
                        sentences1.append(f"Detected unsecured VMs:{detected_vm_count}")

                        print(f"\tTotal Disks checked:", total_disk_checked_count)
                        sentences1.append(f"Total Disks checked: {total_disk_checked_count}")

                        print(f"\tDetected unsecured Disks:", detected_disk_count)
                        sentences1.append(f"Detected unsecured Disks:{detected_disk_count}")

                        #print("\tInsecure VMs:", insecure_vms)
                        #sentences1.append

                        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------------")  # Add a newline for better readability

                    #Call the save to csv function for html report
                    vm_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
                    vm_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)

        except Exception as e:
                print(f'Error in checking virtual machines vulnerabilities: {e}')
                sentences2.append(f'Error in checking virtual machines vulnerabilities: {e}')
                sentences3.append(f'Error in checking virtual machines vulnerabilities: {e}')

except Exception as e:
    print(f"Error In Checking VM Code: {e}")







#################################################################################################
#################################################################################################
#################################################################################################






# Network Code:
try:
    def network_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
        fieldnames = ["Date Time"]
        with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["------Detecting Vulnerabilities in Networking Services------\n"])
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
            writer.writerow(["------Detecting Vulnerabilities in Networking Services------\n"])
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
        print(f"------Detecting Vulnerabilities in Networking------")
        total_nsg_checks = 0
        detected_nsg_count = 0
        total_network_watcher_checks = 0
        detected_network_watcher_count = 0  #network watchers which are not provisioned to succeed
        detected_nsg_names = []
        detected_nsg_resource_groups = []
        detected_network_watcher_names = []
        detected_network_watcher_resource_groups = []
        csv_file_path = "azure_HTML_report.csv"
        datetime_now = datetime.now()
        sentences1 = [] # Details of count
        sentences2 = [] # All details for HTML report
        csv_file_path2 = "Azure_Report.csv"
        sentences3 = [] # Specific detail for users to see vulnerabilities only

        try:
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


                            if not nsg:
                                #print(f"No NSGs found in the '{resource_group.name}' resource group.")
                                sentences2.append(f"No NSGs found in the '{resource_group.name}' resource group.")
                                sentences3.append(f"No NSGs found in the '{resource_group.name}' resource group.")
                            else:
                                total_nsg_checks += 1
                                #print(f"\tNSG named '{nsg.name}'found in the '{resource_group.name}' resource group.")
                                sentences2.append(f"\tNSG named '{nsg.name}'found in the '{resource_group.name}' resource group.")
                                sentences3.append(f"\tNSG named '{nsg.name}'found in the '{resource_group.name}' resource group.")

                            allowed_protocols = {'ssh', 'http', 'rdp', 'https'}
                            allowed_rules = [find_security_rule_by_name(nsg, protocol) for protocol in allowed_protocols]
                            allowed_rules = [rule for rule in allowed_rules if rule and is_access_allow(rule)]

                            # Check if there are more than one allowed rules
                            if len(allowed_rules) > 1:
                                print(f"The NSG '{nsg.name}'in the resource group '{resource_group.name}'")
                                print(f"\tVulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed (Consider Restricting)")
                                sentences2.append(f"\tVulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed (Consider Restricting)")
                                sentences3.append(f"\tVulnerability: Multiple rules of SSH, HTTP, RDP, HTTPS are allowed (Consider Restricting)")
                                print(f"\tAllowed Protocols:")
                                sentences2.append(f"\tAllowed Protocols:")
                                sentences3.append(f"\tAllowed Protocols:")
                                for rule in allowed_rules:
                                    print(f"\t - {rule.name}")
                                    sentences2.append(f"\t - {rule.name}")
                                    sentences3.append(f"\t - {rule.name}")
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

                                if udp_detected:
                                    detected_nsg_count += 1
                                    print(f"The NSG '{nsg.name}'in the resource group '{resource_group.name}'")
                                    print(f"\tWarning: Inbound UDP access is allowed.")
                                    sentences2.append(f"\tWarning: Inbound UDP access is allowed.")
                                    sentences3.append(f"\tWarning: Inbound UDP access is allowed.")

                                if rdp_detected:
                                    detected_nsg_count += 1
                                    print(f"The NSG '{nsg.name}'in the resource group '{resource_group.name}'")
                                    print(f"\tWarning: Inbound RDP access is allowed.")
                                    sentences2.append(f"\tWarning: Inbound RDP access is allowed.")
                                    sentences3.append(f"\tWarning: Inbound RDP access is allowed.")



                            # Recording information for CSV
                            detected_nsg_names.append(nsg.name)
                            detected_nsg_resource_groups.append(resource_group.name)


                    except Exception as e:
                        print(f'Error checking NSG vulnerabilities: {e}')
                        sentences2.append(f'Error checking NSG vulnerabilities: {e}')
                        sentences3.append(f'Error checking NSG vulnerabilities: {e}')

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

                            if not network_watcher:
                                print(f"\tVulnerability: No Network Watchers found in the '{resource_group.name}' resource group. Network Watcher is disabled.")
                                sentences2.append(f"\t1. Vulnerability: No Network Watchers found in the '{resource_group.name}' resource group. Network Watcher is disabled.")
                                sentences3.append(f"\t1. Vulnerability: No Network Watchers found in the '{resource_group.name}' resource group. Network Watcher is disabled.")
                            else:
                                total_network_watcher_checks += 1
                                #print(f"\t1. Network Watcher named '{network_watcher.name}' is Enabled in the '{resource_group.name}' resource group.")
                                sentences2.append(f"\t1. Network Watcher named '{network_watcher.name}' is Enabled in the '{resource_group.name}' resource group.")

                            # Check if Network Watcher is  provisioned successfully
                            if network_watcher.provisioning_state.lower() == 'succeeded':
                                #print(f"\t2. Network Watcher named '{network_watcher.name}' is provisioned successfully.")
                                sentences2.append(f"\t2. Network Watcher named '{network_watcher.name}' is provisioned successfully.")
                            else:
                                detected_network_watcher_count += 1
                                print(f"\tVulnerability: Network Watcher named '{network_watcher.name}' provisioning is not in a successful state.")
                                sentences2.append(f"\t2. Vulnerability: Network Watcher named '{network_watcher.name}' provisioning is not in a successful state.")
                                sentences3.append(f"\t2. Vulnerability: Network Watcher named '{network_watcher.name}' provisioning is not in a successful state.")

                            if network_watcher and network_watcher.provisioning_state.lower() == 'succeeded':
                                sentences2.append(f"\tNo vulnerability Found !")
                                sentences3.append(f"\tNo vulnerability Found !")

                            # Recording information for CSV
                            detected_network_watcher_names.append(network_watcher.name)
                            detected_network_watcher_resource_groups.append(resource_group.name)
                        

                    except Exception as e:
                        print(f'Error checking network watchers: {e}')
                        sentences2.append(f'Error checking network watchers: {e}')
                        sentences3.append(f'Error checking network watchers: {e}')

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
                        
                        print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")

                    #Call the save to csv function for html report
                    network_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
                    network_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)


        except Exception as e:
            print(f'Error in checking network resources: {e}')
            sentences2.append(f'Error in checking network resources: {e}')
            sentences3.append(f'Error in checking network resources: {e}')


except Exception as e:
    print(f"Error In Checking Network Code: {e}")







#################################################################################################
#################################################################################################
#################################################################################################





# Web App Code
try:
    def webapp_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
        fieldnames = ["Date Time"]
        with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["------Detecting Vulnerabilities in Web Apps------\n"])
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

    def webapp_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3):
        fieldnames = ["Date Time"]
        with open(csv_file_path2, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["------Detecting Vulnerabilities in Web Apps------\n"])
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


    def check_web_app(subscription_ids):
        print(f"------Detecting Vulnerabilities in App Services------")
        total_web_apps_checked = 0
        total_detected_web_apps = 0
        csv_file_path = "azure_HTML_report.csv"
        datetime_now = datetime.now()
        sentences1 = [] # Details of count
        sentences2 = [] # All details for HTML report
        csv_file_path2 = "Azure_Report.csv"
        sentences3 = [] # Specific detail for users to see vulnerabilities only

        try:
            credential = DefaultAzureCredential()
            subscription_client = SubscriptionClient(credential)
            subscriptions = list(subscription_client.subscriptions.list())

            for subscription_id in subscription_ids:
                webapp_client = WebSiteManagementClient(credential, subscription_id)    
                resource_client = ResourceManagementClient(credential, subscription_id)
                resource_groups = resource_client.resource_groups.list()

                for resource_group in resource_groups:
                    web_apps = webapp_client.web_apps.list_by_resource_group(resource_group.name)
                    sentences2.append(f"\nIn Resource Group: {resource_group.name}")
                    
                    for web_app in web_apps:
                        total_web_apps_checked += 1
                        print(f"\n")# After every web app
                        sentences3.append(f"\n")

                        auth_settings = webapp_client.web_apps.get_auth_settings(resource_group.name, web_app.name)
                        web_app_configuration = webapp_client.web_apps.get_configuration(resource_group.name, web_app.name)

                        if not auth_settings.enabled:
                            print(f"\n> Vulnerability: App Service Authentication Disabled for WebApp '{web_app.name}'")
                            #print(f"\n\tDescription : Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.")
                            sentences2.append(f"\n\t> Vulnerability: App Service Authentication Disabled for WebApp '{web_app.name}'")
                            sentences2.append(f"\tDescription : Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.")
                            sentences3.append(f"> Vulnerability: App Service Authentication Disabled for WebApp '{web_app.name}'")
                        else:
                            #print(f"\n\t> App Service Authentication Enabled for WebApp '{web_app.name}'")
                            #print(f"\n\tDescription : Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.")
                            sentences2.append(f"\n\t> App Service Authentication Enabled for WebApp '{web_app.name}'")
                            sentences2.append(f"\n\tDescription : Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.")

                        # if auth_settings.aad_claims_authorization is None:
                        #     print(f"> Vulnerability: Azure Active Directory (AAD) Claims Authorization for WebApp '{web_app.name}' is not configured.")
                        #     sentences2.append(f"\t> Vulnerability: Azure Active Directory (AAD) Claims Authorization for WebApp '{web_app.name}' is not configured.")
                        #     sentences3.append(f"> Vulnerability: Azure Active Directory (AAD) Claims Authorization for WebApp '{web_app.name}' is not configured.")
                        # else:
                        #     print(f"\t> Azure Active Directory (AAD) Claims Authorization Status for the WebApp '{web_app.name}' is configured with '{auth_settings.aad_claims_authorization}'")
                        #     sentences2.append(f"\t> Azure Active Directory (AAD) Claims Authorization Status for the WebApp '{web_app.name}' is configured with '{auth_settings.aad_claims_authorization}'")

                        if auth_settings.unauthenticated_client_action == 'AllowAnonymous':
                            print(f"> Vulnerability: Unauthenticated Client Action for WebApp '{web_app.name}' is set to Allow Anonymous")
                            sentences2.append(f"\t> Vulnerability: Unauthenticated Client Action for WebApp '{web_app.name}' is set to Allow Anonymous")
                            sentences3.append(f"> Vulnerability: Unauthenticated Client Action for WebApp '{web_app.name}' is set to Allow Anonymous")
                        else:
                            #print(f"\t> Unauthenticated Client Action for WebApp '{web_app.name}' is not set to Allow Anonymous")
                            sentences2.append(f"\t> Unauthenticated Client Action for WebApp '{web_app.name}' is not set to Allow Anonymous")

                        if not web_app_configuration.auto_heal_enabled:
                            print(f"> Warning: If auto-healing is disabled, WebApp '{web_app.name}' might not recover automatically from failures, leading to potential downtime.")
                            sentences2.append(f"\t> Warning: If auto-healing is disabled, WebApp '{web_app.name}' might not recover automatically from failures, leading to potential downtime.")
                            sentences3.append(f"> Warning: If auto-healing is disabled, WebApp '{web_app.name}' might not recover automatically from failures, leading to potential downtime.")
                        else:
                            #print(f"\t> Auto heal feature is enabled for WebApp '{web_app.name}'")
                            sentences2.append(f"\t> Auto heal feature is enabled for WebApp '{web_app.name}'")

                        # if  web_app_configuration.http_logging_enabled:
                        #     print(f"\t> Warning: If HTTP logging is disabled, it may hinder the ability to monitor and troubleshoot issues for WebApp '{web_app.name}'.")
                            # sentences2.append(f"\t> Warning: If HTTP logging is disabled, it may hinder the ability to monitor and troubleshoot issues for WebApp '{web_app.name}'.")
                            # sentences3.append(f"5. > Warning: If HTTP logging is disabled, it may hinder the ability to monitor and troubleshoot issues for WebApp '{web_app.name}'.")
                        # else:
                        #     print(f"\t> HTTP logging is enabled for WebApp '{web_app.name}'")
                            # sentences2.append(f"\t> HTTP logging is enabled for WebApp '{web_app.name}'")

                        if not web_app_configuration.http20_enabled:
                            print(f"> Warning: HTTP2.0 is disabled for WebApp '{web_app.name}', it may impact the performance benefits provided by the protocol.")
                            sentences2.append(f"\t> Warning: HTTP2.0 is disabled for WebApp '{web_app.name}', it may impact the performance benefits provided by the protocol.")
                            sentences3.append(f"> Warning: HTTP2.0 is disabled for WebApp '{web_app.name}', it may impact the performance benefits provided by the protocol.")
                        else:
                            #print(f"\t> HTTP2.0 is Enabled for WebApp '{web_app.name}'")
                            sentences2.append(f"\t> HTTP2.0 is Enabled for WebApp '{web_app.name}'")

                        if not float(web_app_configuration.min_tls_version) <= 1.2:
                            print(f"> Warning: The TLS (Transport Layer Security) protocol for WebApp '{web_app.name}' secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS.")
                            sentences2.append(f"\t> Warning: The TLS (Transport Layer Security) protocol for WebApp '{web_app.name}' secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS.")
                            sentences3.append(f"> Warning: The TLS (Transport Layer Security) protocol for WebApp '{web_app.name}' secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS.")
                        else:
                            #print(f"\t> TLS (Transport Layer Security) protocol version for WebApp '{web_app.name}' is {web_app_configuration.min_tls_version}")
                            sentences2.append(f"\t> TLS (Transport Layer Security) protocol version for WebApp '{web_app.name}' is {web_app_configuration.min_tls_version}")

                        # if not web_app_configuration.ftps_state == "FtpsOnly":
                        #     print(f"\t> Vulnerability: If FTPS state is not set to 'FtpsOnly', it may expose data in transit to security risks for WebApp '{web_app.name}'.")
                            # sentences2.append(f"\t> Vulnerability: If FTPS state is not set to 'FtpsOnly', it may expose data in transit to security risks for WebApp '{web_app.name}'.")
                            # sentences3.append(f"> Vulnerability: If FTPS state is not set to 'FtpsOnly', it may expose data in transit to security risks for WebApp '{web_app.name}'.")
                        # else:
                        #     print(f"\t> FTPS state is set to 'FtpsOnly' for WebApp '{web_app.name}'")
                            # sentences2.append(f"\t> FTPS state is set to 'FtpsOnly' for WebApp '{web_app.name}'")

                        if web_app_configuration.public_network_access == "Enabled":
                            print(f"> Vulnerability: Enabling public network access may expose the WebApp '{web_app.name}' to potential external threats.")
                            sentences2.append(f"\t> Vulnerability: Enabling public network access may expose the WebApp '{web_app.name}' to potential external threats.")
                            sentences3.append(f"> Vulnerability: Enabling public network access may expose the WebApp '{web_app.name}' to potential external threats.")
                        else:
                            #print(f"\t> Public Network access is disabled to the WebApp '{web_app.name}'")
                            sentences2.append(f"\t> Public Network access is disabled to the WebApp '{web_app.name}'")

                        if web_app_configuration.managed_service_identity_id is None:
                            print(f"> Vulnerability: Managed Service Identity not configured for WebApp '{web_app.name}', leaving it potentially insecure.")
                            #print(f"\t1> Vulnerability: App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps & here for WebApp '{web_app.name}', which is a turn-key solution for securing access to Azure SQL Database and other Azure services.")
                            sentences2.append(f"\t> Vulnerability: Managed Service Identity not configured for WebApp '{web_app.name}', leaving it potentially insecure.")
                            sentences2.append(f"\t> App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps & here for WebApp '{web_app.name}', which is a turn-key solution for securing access to Azure SQL Database and other Azure services.")
                            sentences3.append(f"> Vulnerability: Managed Service Identity not configured for WebApp '{web_app.name}', leaving it potentially insecure.")
                        else:
                            #print(f"\t> Managed Service Identities is Enabled for WebApp '{web_app.name}'")
                            sentences2.append(f"\t> Managed Service Identities is Enabled for WebApp '{web_app.name}',which is {web_app_configuration.managed_service_identity_id}")

                        if (
                            not auth_settings.enabled
                            or auth_settings.aad_claims_authorization is None
                            or auth_settings.unauthenticated_client_action == 'AllowAnonymous'
                            or not web_app_configuration.managed_service_identity_id
                            or web_app_configuration.public_network_access == "Enabled"
                            or not web_app_configuration.auth_settings
                        ):
                            total_detected_web_apps += 1
                        
                        

                for sub in subscriptions:
                    if sub.subscription_id == subscription_id:
                        print(f"\nSubscription Name: {sub.display_name}")
                        sentences1.append(f"\nSubscription Name: {sub.display_name}")
                        sentences1.append(f"Subscription ID: {sub.subscription_id}")

                        print(f"\tTotal Web Apps Checked: {total_web_apps_checked}")
                        sentences1.append(f"\nTotal Web Apps Checked: {total_web_apps_checked}")

                        print(f"\tTotal Detected Web Apps: {total_detected_web_apps}")
                        sentences1.append(f"Total Detected Web Apps: {total_detected_web_apps}")

                        print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")
                    
                    #Call the save to csv function for html report
                    webapp_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
                    webapp_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)

        except Exception as e:
            print(f'Error in checking web app vulnerabilities: {e}')
            sentences2.append(f'Error in checking web app vulnerabilities: {e}')
            sentences3.append(f'Error in checking web app vulnerabilities: {e}')

except Exception as e:
    print(f"Error in checking web app code: {e}")







#################################################################################################
#################################################################################################
#################################################################################################






# Storage Code
try:
    def storageacc_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
        fieldnames = ["Date Time"]
        with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["------Detecting Vulnerabilities in Storage Accounts------\n"])
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

    def storageacc_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3):
        fieldnames = ["Date Time"]
        with open(csv_file_path2, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["------Detecting Vulnerabilities in Storage Accounts------\n"])
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


    def check_storage_account_vulnerabilities(subscription_ids):
        print(f"\nDetecting Vulnerabilities in Storage Accounts...")
        total_checks = 0
        detected_count = 0
        csv_file_path = "azure_HTML_report.csv"
        datetime_now = datetime.now()
        sentences1 = [] # Details of count
        sentences2 = [] # All details for HTML report
        csv_file_path2 = "Azure_Report.csv"
        sentences3 = [] # Specific detail for users to see vulnerabilities only

        # Use Azure SDK with managed identity
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())

        for subscription_id in subscription_ids:
            try:
                # subscription_client = SubscriptionClient(credential)
                storage_client = StorageManagementClient(credential, subscription_id)
                storage_accounts = storage_client.storage_accounts.list()

                for storage_account in storage_accounts:
                    # print("\n1. Storage Account",storage_account)
                    total_checks += 1
                    print(f"\n")# After every storage account

                    # Ensure that 'Secure transfer required' is set to 'Enabled'
                    if not storage_account.enable_https_traffic_only:
                        print(f"\n> Vulnerability: The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS).")
                        sentences2.append(f"\t1. Vulnerability: The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS).")
                        sentences3.append(f"> Vulnerability: The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS).")
                    else:
                        #print(f"\n\t1. The Storage Account '{storage_account.name}' has enforced Secure transfer (HTTPS).")
                        sentences2.append(f"\t1. The Storage Account '{storage_account.name}' has enforced Secure transfer (HTTPS).")
                        
                    #Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’
                    if not storage_account.encryption.require_infrastructure_encryption:
                        print(f"> Vulnerability: The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption.")
                        sentences2.append(f"\t2. Vulnerability: The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption.")
                        sentences3.append(f"> Vulnerability: The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption.")
                    else:
                        #print(f"\t2. The Storage Account '{storage_account.name}' has enabled Infrastructure Encryption.")
                        sentences2.append(f"\t2. The Storage Account '{storage_account.name}' has enabled Infrastructure Encryption.")

                    #Ensure that 'Public access level' is disabled for storage accounts with blob containers 
                    if storage_account.allow_blob_public_access:
                        print(f"> Vulnerability : The Storage Account '{storage_account.name}' with blob containers has allowed public access.")
                        sentences2.append(f"\t3. Vulnerability : The Storage Account '{storage_account.name}' with blob containers has allowed public access.")
                        sentences3.append(f"> Vulnerability : The Storage Account '{storage_account.name}' with blob containers has allowed public access.")
                    else:
                        #print(f"\t3. The Storage Account '{storage_account.name}'with blob containers has denied public access.")
                        sentences2.append(f"\t3. The Storage Account '{storage_account.name}'with blob containers has denied public access.")

                    ## Ensure Default Network Access Rule for Storage Accounts is Set to Deny
                    if storage_account.public_network_access:
                        print(f"> Vulnerability: The Storage Account '{storage_account.name}' is allowing public traffic.")
                        sentences2.append(f"\t4. Vulnerability: The Storage Account '{storage_account.name}' is allowing public traffic.")
                        sentences3.append(f"> Vulnerability: The Storage Account '{storage_account.name}' is allowing public traffic.")
                    else:
                        #print(f"\t4. The Storage Account '{storage_account.name}' has denied the public traffic.")
                        sentences2.append(f"\t4. The Storage Account '{storage_account.name}' has denied the public traffic.")

                    #Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2"
                    if not storage_account.minimum_tls_version == 'TLS1_2':
                        print(f"> Warning: The Storage Account '{storage_account.name}' uses an outdated TLS version ({storage_account.minimum_tls_version}). Update to TLS Version 1.2 for enhanced security.")
                        sentences2.append(f"\t5. Warning: The Storage Account '{storage_account.name}' uses an outdated TLS version ({storage_account.minimum_tls_version}). Update to TLS Version 1.2 for enhanced security.")
                        sentences3.append(f"> Warning: The Storage Account '{storage_account.name}' uses an outdated TLS version ({storage_account.minimum_tls_version}). Update to TLS Version 1.2 for enhanced security.")
                    else:
                        #print(f"\t5. TLS version for The Storage Account '{storage_account.name}' is up to date: {storage_account.minimum_tls_version}.")
                        sentences2.append(f"\t5. TLS version for The Storage Account '{storage_account.name}' is up to date: {storage_account.minimum_tls_version}.")

                    sentences2.append(f"\n")
                    sentences3.append(f"\n")# After every storage account

                    if (
                        not storage_account.enable_https_traffic_only
                        or not storage_account.encryption.require_infrastructure_encryption
                        or storage_account.allow_blob_public_access
                        or storage_account.public_network_access
                    ):
                        detected_count +=1



            except Exception as e:
                print(f"Error Detecting Vulnerabilities For Storage Account in subscription {subscription_id}: {e}")
                print(f"Please ensure that the 'Storage Blob Data Reader' role is assigned to the subscription.")
                sentences2.append(f"Error Detecting Vulnerabilities For Storage Account in subscription {subscription_id}: {e}")
                sentences2.append(f"Please ensure that the 'Storage Blob Data Reader' role is assigned to the subscription.")
                sentences3.append(f"Error Detecting Vulnerabilities For Storage Account in subscription {subscription_id}: {e}")
                sentences3.append(f"Please ensure that the 'Storage Blob Data Reader' role is assigned to the subscription.")

            for sub in subscriptions:
                if sub.subscription_id == subscription_id:
                    print(f"\nSubscription Name: {sub.display_name}")
                    sentences1.append(f"\nSubscription Name: {sub.display_name}")
                    sentences1.append(f"Subscription ID: {sub.subscription_id}")

                    print(f"\tTotal Storage Accounts Checked: ", total_checks)
                    sentences1.append(f"\nTotal Storage Accounts Checked: {total_checks}")

                    print(f"\tDetected Vulnerable Storage Accounts: ", detected_count)
                    sentences1.append(f"Detected Vulnerable Storage Accounts: {detected_count} \n")

                    print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")

                #Call the save to csv function for html report
                storageacc_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
                storageacc_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)

except Exception as e:
    print(f"Error in checking Storage Account code: {e}")



#################################################################################################
#################################################################################################
#################################################################################################

# Key Vault Code 
try:
    def keyvault_rbac_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
        fieldnames = ["Date Time"]
        with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Detecting Vulnerabilities in Key Vaults ...\n"])
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

    def keyvault_rbac_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3):
        fieldnames = ["Date Time"]
        with open(csv_file_path2, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Detecting Vulnerabilities in Key Vaults ...\n"])
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


    def check_key_vault_rbac(subscription_ids):
        print(f"\n------Detecting Vulnerabilities in Key Vaults & RBAC------")
        total_key_vault_count = 0
        detected_key_vault_count = 0
        csv_file_path = "azure_HTML_report.csv"
        datetime_now = datetime.now()
        sentences1 = [] # Details of count
        sentences2 = [] # All details for HTML report
        csv_file_path2 = "Azure_Report.csv"
        sentences3 = [] # Specific detail for users to see vulnerabilities only


        try:
            credential = DefaultAzureCredential()
            subscription_client = SubscriptionClient(credential)
            subscriptions = list(subscription_client.subscriptions.list())

            for subscription_id in subscription_ids:
                keyvault_client = KeyVaultManagementClient(credential, subscription_id)
                resource_client = ResourceManagementClient(credential, subscription_id)
                resource_groups = resource_client.resource_groups.list()

                for resource_group in resource_groups:
                    keyvaults = keyvault_client.vaults.list_by_resource_group(resource_group.name)

                    for keyvault in keyvaults:
                        total_key_vault_count += 1
                        print(f"\n") #after every key vault
                        sentences2.append(f"\n")
                        sentences3.append(f"\n")

                        # Check if RBAC is enabled
                        if keyvault.properties.enable_rbac_authorization:
                            #print(f"\n> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has RBAC enabled.")
                            sentences2.append(f"\n> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has RBAC enabled.")
                        else:
                            print(f"\n> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have RBAC enabled.")
                            sentences2.append(f"\n> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have RBAC enabled.")
                            sentences3.append(f"\n> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have RBAC enabled.")
                        
                        # Check if key rotation settings are present 
                        if keyvault.properties.enable_soft_delete:
                            #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has key rotation enabled.")
                            sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has key rotation enabled.")
                        else:
                            print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have key rotation enabled.")
                            sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have key rotation enabled.")
                            sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have key rotation enabled.")
                        
                        # Check if Private Endpoint connections are present
                        if keyvault.properties.private_endpoint_connections:
                            #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has Private Endpoint connections.")
                            sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has Private Endpoint connections.")
                        else:
                            print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have Private Endpoint connections.")
                            sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have Private Endpoint connections.")
                            sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have Private Endpoint connections.")
                        
                        # Check if automated recovery is enabled
                        if keyvault.properties.enable_soft_delete and keyvault.properties.enable_purge_protection:
                            #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has automated recovery enabled.")
                            sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has automated recovery enabled.")
                        else:
                            print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have automated recovery enabled.")
                            sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have automated recovery enabled.")
                            sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have automated recovery enabled.")

                        # Check if Key Vault allows public network access
                        network_acls = keyvault.properties.network_acls
                        if network_acls and network_acls.default_action == 'Allow':
                            print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' allows public network access.")
                            sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' allows public network access.")
                            sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' allows public network access.")
                        else:
                            #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not allow public network access.")
                            sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not allow public network access.")

                        # Fetch role assignments for the Key Vault using AuthorizationManagementClient
                        authorization_client = AuthorizationManagementClient(credential, subscription_id)
                        role_assignments = list(authorization_client.role_assignments.list_for_scope(keyvault.id))

                        # Check if a custom subscription owner role is present
                        custom_owner_role_present = any(
                            assignment.role_definition_id.endswith('/subscriptionOwners')
                            for assignment in role_assignments
                        )

                        if custom_owner_role_present:
                            #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has a custom subscription owner role assigned.")
                            sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has a custom subscription owner role assigned.")
                        else:
                            print(f"> Warning: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have a custom subscription owner role assigned.")
                            sentences2.append(f"> Warning: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have a custom subscription owner role assigned.")
                            sentences3.append(f"> Warning: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have a custom subscription owner role assigned.")

    #                    """Check if expiration date is set to be 90 days or less from creation for all secrets in non-RBAC Key Vaults across specified subscriptions."""
    #                 # Construct the Key Vault URL
    #                 keyvault_url = f"https://{keyvault.name}.vault.azure.net"

    #                 # Initialize SecretClient
    #                 secret_client = SecretClient(keyvault_url, credential)

    #                 # List secrets and check expiration date to be 90 days or less from creation
    #                 secrets = secret_client.list_properties_of_secrets()
    #                 for secret in secrets:
    #                     if secret.properties.expires_on is not None:
    #                         expiration_date = secret.properties.expires_on or secret.properties.expires_on_utc

    #                         # Check if the expiration date is 90 days or less from the creation date
    #                         creation_date = secret.properties.created
    #                         if expiration_date <= creation_date + timedelta(days=90):
    #                             print(f"  Secret '{secret.name}' in Key Vault '{keyvault.name}' has a valid expiration date set: {expiration_date}.")
    #                         else:
    #                             print(f"  Warning: Secret '{secret.name}' in Key Vault '{keyvault.name}' has an expiration date more than 90 days from creation: {expiration_date}.")
    #                     else:
    #                         print(f"  Warning: Secret '{secret.name}' in Key Vault '{keyvault.name}' does not have an expiration date set.")


                        if (not keyvault.properties.enable_rbac_authorization
                        or not keyvault.properties.enable_soft_delete
                        or not keyvault.properties.private_endpoint_connections
                        or (network_acls and network_acls.default_action == 'Allow')
                        ):
                            detected_key_vault_count += 1

                    

                for sub in subscriptions:
                    if sub.subscription_id == subscription_id:
                        print(f"\nSubscription Name: {sub.display_name}")
                        sentences1.append(f"\nSubscription Name: {sub.display_name}")
                        sentences1.append(f"Subscription ID: {sub.subscription_id}")

                        print(f"\tTotal Key Vaults Checked: {total_key_vault_count}")
                        sentences1.append(f"\nTotal Key Vaults Checked: {total_key_vault_count}")

                        print(f"\tTotal Detected Key Vaults: {detected_key_vault_count}")
                        sentences1.append(f"Total Detected Key Vaults: {detected_key_vault_count}")

                        print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")
                    
                    #Call the save to csv function for html report
                    keyvault_rbac_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
                    keyvault_rbac_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)


        except Exception as e:
            print(f'Error in checking Vulnerabilities for Key Vault: {e}')
            sentences2.append(f'Error in checking Vulnerabilities for Key Vault: {e}')
            sentences3.append(f'Error in checking Vulnerabilities for Key Vault: {e}')
            

except Exception as e:
    print(f"Error in checking Key Vault code: {e}")






#################################################################################################
#################################################################################################
#################################################################################################


if __name__ == '__main__':
    get_subscriptions()
    subscription_input = input("\nEnter the subscription ID(s) you want to check (comma-separated) or type 'all' for all subscriptions: ")

    if subscription_input.lower() == 'all':
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscription_ids = [sub.subscription_id for sub in subscription_client.subscriptions.list()]
    else:
        subscription_ids = [sub.strip() for sub in subscription_input.split(',')]

    check_unsecured_vm_instances(subscription_ids)
    check_network(subscription_ids)
    check_web_app(subscription_ids)
    check_storage_account_vulnerabilities(subscription_ids)
    check_key_vault_rbac(subscription_ids)

