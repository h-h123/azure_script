import csv
from datetime import datetime
from collections import defaultdict
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient





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





#################################################################################################
#################################################################################################
#################################################################################################




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







#################################################################################################
#################################################################################################
#################################################################################################




def check_web_app(subscription_ids):
    total_web_apps_checked = 0
    total_detected_web_apps = 0
    try:
        credential = DefaultAzureCredential()

        for subscription_id in subscription_ids:
            webapp_client = WebSiteManagementClient(credential, subscription_id)    
            resource_client = ResourceManagementClient(credential, subscription_id)
            resource_groups = resource_client.resource_groups.list()

            for resource_group in resource_groups:
                web_apps = webapp_client.web_apps.list_by_resource_group(resource_group.name)
                
                for web_app in web_apps:
                    total_web_apps_checked += 1

                    auth_settings = webapp_client.web_apps.get_auth_settings(resource_group.name, web_app.name)
                    web_app_configuration = webapp_client.web_apps.get_configuration(resource_group.name, web_app.name)

                    if not auth_settings.enabled:
                        print(f"\n\tApp Service Authentication Disabled for {web_app.name}")
                        print(f"\n\tDescription : Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.")
                    else:
                        print(f"\n\tApp Service Authentication Enabled for {web_app.name}")
                        print(f"\n\tDescription : Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.")

                    if auth_settings.aad_claims_authorization is None:
                        print(f"\n\tVulnerability: AAD Claims Authorization for {web_app.name}: None")
                    else:
                        print(f"\n\tAAD Claims Authorization for {web_app.name}: {auth_settings.aad_claims_authorization}")

                    if auth_settings.unauthenticated_client_action == 'AllowAnonymous':
                        print(f"\n\tVulnerability: Unauthenticated Client Action for {web_app.name}: Allow Anonymous")
                    else:
                        print(f"\n\tUnauthenticated Client Action for {web_app.name}: Not Allow Anonymous")

                    if not web_app_configuration.auto_heal_enabled:
                        print(f"\n\tWarning: If auto-healing is disabled, the {web_app.name} web app might not recover automatically from failures, leading to potential downtime.")
                    else:
                        print(f"\n\tAutoheal feature is enabled for {web_app.name}")

                    if  web_app_configuration.http_logging_enabled:
                        print(f"\n\tWarning: If HTTP logging is disabled, it may hinder the ability to monitor and troubleshoot issues for {web_app.name}.")
                    else:
                        print(f"\n\tHTTP logging is enabled for {web_app.name}")

                    if not web_app_configuration.http20_enabled:
                        print(f"\n\tWarning: HTTP2.0 is disabledfor {web_app.name}, it may impact the performance benefits provided by the protocol.")
                    else:
                        print(f"\n\tHTTP2.0 is Enabled for {web_app.name}")

                    if not float(web_app_configuration.min_tls_version) <= 1.2:
                        print(f"\n\tWarning: The TLS (Transport Layer Security) protocol for {web_app.name} secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS.")
                    else:
                        print(f"\n\tTLS (Transport Layer Security) protocol version for {web_app.name}:", web_app_configuration.min_tls_version)

                    if not web_app_configuration.ftps_state == "FtpsOnly":
                        print(f"\n\tVulnerability: If FTPS state is not set to 'FtpsOnly', it may expose data in transit to security risks for {web_app.name}.")
                    else:
                        print(f"\n\tFTPS state is set to 'FtpsOnly' for {web_app.name}")

                    if web_app_configuration.public_network_access == "Enabled":
                        print(f"\n\tVulnerability: Enabling public network access may expose the web app named {web_app.name} to potential external threats.")
                    else:
                        print(f"\n\tPublic Network access is disabled to the {web_app.name} web app ")

                    if web_app_configuration.managed_service_identity_id is None:
                        print(f"\n\tVulnerability: App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps & here for {web_app.name}, which is a turn-key solution for securing access to Azure SQL Database and other Azure services.")
                    else:
                        print(f"\n\tManaged Service Identities is Enabled for {web_app.name}")

                    if (
                        not auth_settings.enabled
                        or auth_settings.aad_claims_authorization is None
                        or auth_settings.unauthenticated_client_action == 'AllowAnonymous'
                        or not web_app_configuration.managed_service_identity_id
                        or web_app_configuration.public_network_access == "Enabled"
                        or not web_app_configuration.auth_settings
                    ):
                        total_detected_web_apps += 1



    except Exception as e:
        print(f'Error in checking web app vulnerabilities: {e}')

    print("---------------------------------------------------------------------------------")
    print(f"\nTotal Web Apps Checked: {total_web_apps_checked}")
    print(f"Total Detected Web Apps: {total_detected_web_apps}")







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
