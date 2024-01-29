import csv
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.keyvault.secrets import SecretClient
from azure.mgmt.authorization import AuthorizationManagementClient

def get_subscriptions():
    try:
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())

        print("Available Subscriptions:")
        for sub in subscriptions:
            print(f"Subscription Name: {sub.display_name}, Subscription ID: {sub.subscription_id}\n")

        return subscriptions
    except Exception as e:
        print(f"Error retrieving subscriptions: {e}")
        raise




#######################################################################################################

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

def new_Report_keyvault_rbac_sentences1and2_save_to_csv_for_html_report(csv_file_path3, datetime_now, details_dict):
    fieldnames = ["Date Time", "Subscription Name", "Subscription ID", "Total Key Vaults Checked", "Total Detected Key Vaults", "Details"]
    
    with open(csv_file_path3, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if file.tell() == 0:
            writer.writeheader()

        # Use details_dict directly
        data = {
            "Date Time": datetime_now,
            "Subscription Name": details_dict.get("Subscription Name", ""),
            "Subscription ID": details_dict.get("Subscription ID", ""),
            "Total Key Vaults Checked": details_dict.get("Total Key Vaults Checked", ""),
            "Total Detected Key Vaults": details_dict.get("Total Detected Key Vaults", ""),
            "Details": ', \n'.join(details_dict.get("Details", []))  # Join the list of sentences into a string
        }

        writer.writerow(data)



#######################################################################################################


def check_key_vault_rbac(subscription_ids): 
    total_key_vault_count = 0
    detected_key_vault_count = 0
    csv_file_path = "azure_HTML_report.csv"
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
    "Total Key Vaults Checked": 0,
    "Total Detected Key Vaults": 0,
    "Details": []  # Details will be a list of sentences
    }


    try:
        print(f"\n------Detecting Vulnerabilities in Key Vaults & RBAC------")
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
                    details_dict["Details"].append(f"\n")

                    # Check if RBAC is enabled
                    if keyvault.properties.enable_rbac_authorization:
                        #print(f"\n> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has RBAC enabled.")
                        sentences2.append(f"\n> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has RBAC enabled.")
                        details_dict["Details"].append(f"\n> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has RBAC enabled.")
                    else:
                        print(f"\n> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have RBAC enabled.")
                        sentences2.append(f"\n> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have RBAC enabled.")
                        sentences3.append(f"\n> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have RBAC enabled.")
                        details_dict["Details"].append(f"\n> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have RBAC enabled.")

                    # Check if key rotation settings are present 
                    if keyvault.properties.enable_soft_delete:
                        #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has key rotation enabled.")
                        sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has key rotation enabled.")
                        details_dict["Details"].append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has key rotation enabled.")
                    else:
                        print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have key rotation enabled.")
                        sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have key rotation enabled.")
                        sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have key rotation enabled.")
                        details_dict["Details"].append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have key rotation enabled.")

                    # Check if Private Endpoint connections are present
                    if keyvault.properties.private_endpoint_connections:
                        #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has Private Endpoint connections.")
                        sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has Private Endpoint connections.")
                        details_dict["Details"].append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has Private Endpoint connections.")
                    else:
                        print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have Private Endpoint connections.")
                        sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have Private Endpoint connections.")
                        sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have Private Endpoint connections.")
                        details_dict["Details"].append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have Private Endpoint connections.")

                    # Check if automated recovery is enabled
                    if keyvault.properties.enable_soft_delete and keyvault.properties.enable_purge_protection:
                        #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has automated recovery enabled.")
                        sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has automated recovery enabled.")
                        details_dict["Details"].append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has automated recovery enabled.")
                    else:
                        print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have automated recovery enabled.")
                        sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have automated recovery enabled.")
                        sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have automated recovery enabled.")
                        details_dict["Details"].append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have automated recovery enabled.")

                    # Check if Key Vault allows public network access
                    network_acls = keyvault.properties.network_acls
                    if network_acls and network_acls.default_action == 'Allow':
                        print(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' allows public network access.")
                        sentences2.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' allows public network access.")
                        sentences3.append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' allows public network access.")
                        details_dict["Details"].append(f"> Vulnerability: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' allows public network access.")
                    else:
                        #print(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not allow public network access.")
                        sentences2.append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not allow public network access.")
                        details_dict["Details"].append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not allow public network access.")

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
                        details_dict["Details"].append(f"> Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' has a custom subscription owner role assigned.")
                    else:
                        print(f"> Warning: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have a custom subscription owner role assigned.")
                        sentences2.append(f"> Warning: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have a custom subscription owner role assigned.")
                        sentences3.append(f"> Warning: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have a custom subscription owner role assigned.")
                        details_dict["Details"].append(f"> Warning: Azure Key Vault '{keyvault.name}' in Resource Group '{resource_group.name}' does not have a custom subscription owner role assigned.")

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

                    print(f"-" * 160)
                    #print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")
                
                    # Add details_dict to sentences1 list
                    details_dict["Subscription Name"] = sub.display_name
                    details_dict["Subscription ID"] = sub.subscription_id
                    details_dict["Total Key Vaults Checked"] = total_key_vault_count
                    details_dict["Total Detected Key Vaults"] = detected_key_vault_count
                #Call the save to csv function for html report
                keyvault_rbac_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
                keyvault_rbac_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)
                new_Report_keyvault_rbac_sentences1and2_save_to_csv_for_html_report(csv_file_path3, datetime_now, details_dict)

    except Exception as e:
        print(f'Error in checking Vulnerabilities for Key Vault: {e}')
        sentences2.append(f'Error in checking Vulnerabilities for Key Vault: {e}')
        sentences3.append(f'Error in checking Vulnerabilities for Key Vault: {e}')
        details_dict["Details"].append(f'Error in checking Vulnerabilities for Key Vault: {e}')
        

if __name__ == '__main__':
    subscriptions = get_subscriptions()
    subscription_input = input(f"\nEnter the subscription ID(s) you want to check (comma-separated) or type 'all' for all subscriptions: ")

    if subscription_input.lower() == 'all':
        subscription_ids = [sub.subscription_id for sub in subscriptions]
    else:
        subscription_ids = [sub.strip() for sub in subscription_input.split(',')]

    check_key_vault_rbac(subscription_ids)
