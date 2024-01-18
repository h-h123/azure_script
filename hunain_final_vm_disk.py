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


def write_vm_info_to_csv(writer, subscription_name, subscription_id, vm_name, open_ports, unsecured,  encryption, data_access_auth_mode):
    datetime_value = datetime.now()
    writer.writerow([datetime_value, subscription_name, subscription_id, vm_name, 'Yes' if open_ports else 'No', 'Yes' if unsecured else 'No', 'Configured' if encryption else 'Not Configured', 'No Authentication' if data_access_auth_mode is None else 'Secure'])


def check_disk_vulnerability_warning_scenarios(disk):
    # Virtual Machines Not Utilizing Managed Disks
    if disk.type:
        print("\n\tThe virtual machine is using a managed disk.")
    else:
        print("\n\tThe virtual machine is not using a managed disk.")


    # Data Access Auth Mode
    if disk.data_access_auth_mode is None:
        print("\n\t1.Potential Vulnerability: Data Access Authentication Mode is configured with weak or no authentication.")
        print("\tRisk: Unauthorized users may gain access to sensitive disk data, leading to potential data breaches.")
        print("\tRecommendation: Ensure strong authentication methods, such as Azure AD/ Entra ID credentials, are enforced.")
    else:
        print("\n\t1.Data Access Authentication Mode is configured (Secure)")

    # Encryption Settings
    if not disk.encryption:
        print("\n\t2.Potential Vulnerability: Encryption settings are not configured.")
    else:
        print("\n\t2.Encryption settings are configured.")

    # Optimized for Frequent Attach
    if disk.optimized_for_frequent_attach and 'sensitive_data' in disk.tags:
        print("\n\t3.Warning: Disk is optimized for frequent attachment, but it contains sensitive data.")
        print("\tRisk: Frequent attaching may expose the disk to unintended access, increasing the risk of data compromise.")
        print("\tRecommendation: Assess the need for frequent attachment and optimize performance accordingly. Consider encryption for sensitive data.")
    else:
        print("\n\t3.The disk is not configured for frequent attachment optimization or does not contain sensitive data.")
        print("\tExplanation: Frequent attachment optimization is not applicable, and the disk does not pose a risk of unintended access or data compromise.")

    # Bursting Enabled Time
    if disk.bursting_enabled_time and disk.bursting_enabled_time.startswith("peak_hours"):
        print("\n\t4.Warning: Bursting is currently enabled during peak operational hours.")
        print("\tRisk: Bursting might consume additional resources, impacting overall system performance during peak hours.")
        print("\tRecommendation: Schedule bursting during non-peak hours and monitor resource utilization to avoid performance degradation.")
    else:
        print("\n\t4.Bursting is either not enabled or not configured for peak operational hours.")

    
    # # Disk Size in GB
    # used_storage_gb = # You need to obtain the actual used storage value for the disk
    # if used_storage_gb is not None and used_storage_gb >= 0:
    #     if used_storage_gb / disk.disk_size_gb >= 0.9:  # Adjust the threshold as needed
    #         print("Disk Size Scenario: Disk storage is approaching full.")
    #     else:
    #         print("Disk Size Scenario: Disk storage is not approaching full.")
    # else:
    #     print("Disk Size Scenario: Unable to determine used storage information.")




def check_unsecured_vm_instances(subscription_ids):
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    subscriptions = list(subscription_client.subscriptions.list())

    for subscription_id in subscription_ids:
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)

        vms = compute_client.virtual_machines.list_all()

        checked_count = 0
        detected_count = 0
        insecure_vms = []
        #vm_details = defaultdict(list)

        with open('Hunain_VM.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Detecting Unsecured VMs"])
            writer.writerow(['DateTime', 'Subscription Name', 'Subscription ID',  'VM Name', 'Open Ports', 'Unsecured', 'Disk Encryption' ,'Disk:Data Access Auth Mode'])

            for vm in vms:
                checked_count += 1

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


                    #Information about Disk in the VM
                    disks_list = compute_client.disks.list_by_resource_group(resource_group_name=vm.id.split("/")[4])
                    #print("1")
                    for disk in disks_list:
                        print(f"\nVM : ",vm.name)
                        print(f"Disk Name: {disk.name}")
                        check_disk_vulnerability_warning_scenarios(disk)

                # Check if all conditions are met before flagging the VM as unsecured
                if has_public_ip_and_open_to_all and overly_permissive_nsg_rule and misconfigured_security_rule:
                    detected_count += 1
                    insecure_vms.append(vm.name)
                    unsecured = True
                    for sub in subscriptions:
                        if sub.subscription_id == subscription_id: 
                            write_vm_info_to_csv(writer, sub.display_name, sub.subscription_id , vm.name, misconfigured_security_rule, unsecured, disk.encryption, disk.data_access_auth_mode)

        # Printing Information
        for sub in subscriptions:
            if sub.subscription_id == subscription_id:
                print(f"\nSubscription Name: {sub.display_name}")
                print("\tTotal VMs checked:", checked_count)
                print("\tDetected unsecured VMs:", len(insecure_vms))
                print("\tInsecure VMs:", insecure_vms)
                print("-------------------------------------------------------------------------------------------------------")  # Add a newline for better readability


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