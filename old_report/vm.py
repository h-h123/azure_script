import csv
from datetime import datetime
from collections import defaultdict
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient

def get_subscriptions():
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    subscriptions = list(subscription_client.subscriptions.list())

    print("Available Subscriptions:")
    for sub in subscriptions:
        print(f"Subscription Name: {sub.display_name}, Subscription ID: {sub.subscription_id}")



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
    csv_file_path = "azure_web_app_HTML_report.csv"
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