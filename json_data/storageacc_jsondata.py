from datetime import datetime
import csv
import os
import json 
from collections import Counter
from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient

def get_subscriptions():
    credential = DefaultAzureCredential()
    subscription_client = SubscriptionClient(credential)
    subscriptions = list(subscription_client.subscriptions.list())

    print("Available Subscriptions:")
    for sub in subscriptions:
        print(f"Subscription Name: {sub.display_name}, Subscription ID: {sub.subscription_id}")

#######################################################################################################

# def storageacc_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
#     fieldnames = ["Date Time"]
#     with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
#         writer = csv.writer(file)
#         writer.writerow(["Detecting Vulnerabilities in Storage Accounts ...\n"])
#         writer.writerow(fieldnames)
#         writer.writerow([datetime_now])
#         # First sentences
#         for sentence in sentences1:
#             writer.writerow([sentence])
#         # Second Sentences
#         for sentence in sentences2:
#             writer.writerow([sentence])
        
#         writer.writerow(["-------------------------------------------------------------------------------------------------------------------------------------------------------------------"])

#######################################################################################################

def storageacc_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3):
    fieldnames = ["Date Time"]
    with open(csv_file_path2, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Detecting Vulnerabilities in Storage Accounts ...\n"])
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

# def new_Report_Storage_Account_sentences1and2_save_to_csv_for_html_report(csv_file_path3, datetime_now, details_dict):
#     fieldnames = ["Date Time", "Subscription Name", "Subscription ID", "Total Storage Accounts Checked", "Total Detected Storage Accounts", "Details"]
    
#     with open(csv_file_path3, mode='a', newline='', encoding='utf-8') as file:
#         writer = csv.DictWriter(file, fieldnames=fieldnames)
#         if file.tell() == 0:
#             writer.writeheader()

#         # Use details_dict directly
#         data = {
#             "Date Time": datetime_now,
#             "Subscription Name": details_dict.get("Subscription Name", ""),
#             "Subscription ID": details_dict.get("Subscription ID", ""),
#             "Total Storage Accounts Checked": details_dict.get("Total Storage Accounts Checked", ""),
#             "Total Detected Storage Accounts": details_dict.get("Total Detected Storage Accounts", ""),
#             "Details": ', \n'.join(details_dict.get("Details", []))  # Join the list of sentences into a string
#         }

#         writer.writerow(data)


#######################################################################################################

def json_report(json_path, datetime_now, details_dict):
    with open(json_path, "w") as outputfile:
        # Use details_dict directly
        data = {
            "Date Time": datetime_now.strftime('%d/%m/%Y  %H:%M:%S'),
            "Subscription Name": details_dict.get("Subscription Name", ),
            "Subscription ID": details_dict.get("Subscription ID", ),
            "Total Storage Accounts Checked": details_dict.get("Total Storage Accounts Checked", ""),
            "Total Detected Storage Accounts": details_dict.get("Total Detected Storage Accounts", ""),
            "Details": details_dict.get("Details", {})  # Join the list of sentences into a string
            # "Details": {k: ', '.join(v) if isinstance(v, list) else v for k, v in details_dict.get("Details", {}).items()}
        }
        json.dump(data, outputfile)


#######################################################################################################


def check_storage_account_vulnerabilities(subscription_ids):
    print(f"\nDetecting Vulnerabilities in Storage Accounts...")
    total_checks = 0
    detected_count = 0
    csv_file_path = "azure_storage_account_HTML_report.csv"
    datetime_now = datetime.now()
    sentences1 = [] # Details of count
    sentences2 = [] # All details for HTML report
    csv_file_path2 = "Azure_Report.csv"
    sentences3 = [] # Specific detail for users to see vulnerabilities only
    csv_file_path3 = 'New_report.csv'
    json_path = "StorageAccount_data.json"
    # Details dictionary for the current subscription
    details_dict = {
    "Subscription Name": "",
    "Subscription ID": "",
    "Total Storage Accounts Checked": 0,
    "Total Detected Storage Accounts": 0,
    "Details": {}  # Details will be a list of sentences
    }


    try:
        # Use Azure SDK with managed identity
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())
        for subscription_id in subscription_ids:
            # subscription_client = SubscriptionClient(credential)
            storage_client = StorageManagementClient(credential, subscription_id)
            storage_accounts = storage_client.storage_accounts.list()

            for storage_account in storage_accounts:
                # print("\n1. Storage Account",storage_account)
                total_checks += 1
                print(f"\n")# After every storage account
                # details_dict["Details"].append(f"\nStorage_Account: {storage_account.name}")
                details_dict["Details"][f"Storage_Account {storage_account.name}"] = storage_account.name

                # Ensure that 'Secure transfer required' is set to 'Enabled'
                if not storage_account.enable_https_traffic_only:
                    print(f"\n\t> Vulnerability: The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS).")
                    sentences2.append(f"\t1. Vulnerability: The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS).")
                    sentences3.append(f"> Vulnerability: The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS).")
                    # details_dict["Details"].append(f"Vulnerability: The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS).")
                    details_dict["Details"][f"Vulnerability - The Storage Account '{storage_account.name}' has not enforced Secure transfer (HTTPS)."] = storage_account.name
                else:
                    #print(f"\n\t1. The Storage Account '{storage_account.name}' has enforced Secure transfer (HTTPS).")
                    sentences2.append(f"\t1. The Storage Account '{storage_account.name}' has enforced Secure transfer (HTTPS).")
                    # details_dict["Details"].append(f"The Storage Account '{storage_account.name}' has enforced Secure transfer (HTTPS).")
                    details_dict["Details"][f"The Storage Account '{storage_account.name}' has enforced Secure transfer (HTTPS)."] = storage_account.name

                #Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’
                if not storage_account.encryption.require_infrastructure_encryption:
                    print(f"\t> Vulnerability: The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption.")
                    sentences2.append(f"\t2. Vulnerability: The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption.")
                    sentences3.append(f"> Vulnerability: The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption.")
                    # details_dict["Details"].append(f"Vulnerability: The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption.")
                    details_dict["Details"][f"Vulnerability - The Storage Account '{storage_account.name}' has not enabled Infrastructure Encryption."] = storage_account.name
                else:
                    #print(f"\t2. The Storage Account '{storage_account.name}' has enabled Infrastructure Encryption.")
                    sentences2.append(f"\t2. The Storage Account '{storage_account.name}' has enabled Infrastructure Encryption.")
                    # details_dict["Details"].append(f"The Storage Account '{storage_account.name}' has enabled Infrastructure Encryption.")
                    details_dict["Details"][f"The Storage Account '{storage_account.name}' has enabled Infrastructure Encryption."] = storage_account.name

                #Ensure that 'Public access level' is disabled for storage accounts with blob containers 
                if storage_account.allow_blob_public_access:
                    print(f"\t> Vulnerability : The Storage Account '{storage_account.name}' with blob containers has allowed public access.")
                    sentences2.append(f"\t3. Vulnerability : The Storage Account '{storage_account.name}' with blob containers has allowed public access.")
                    sentences3.append(f"> Vulnerability : The Storage Account '{storage_account.name}' with blob containers has allowed public access.")
                    # details_dict["Details"].append(f"Vulnerability : The Storage Account '{storage_account.name}' with blob containers has allowed public access.")
                    details_dict["Details"][f"Vulnerability - The Storage Account '{storage_account.name}' with blob containers has allowed public access."] = storage_account.name
                else:
                    #print(f"\t3. The Storage Account '{storage_account.name}'with blob containers has denied public access.")
                    sentences2.append(f"\t3. The Storage Account '{storage_account.name}'with blob containers has denied public access.")
                    # details_dict["Details"].append(f"The Storage Account '{storage_account.name}'with blob containers has denied public access.")
                    details_dict["Details"][f"The Storage Account '{storage_account.name}'with blob containers has denied public access."] = storage_account.name

                ## Ensure Default Network Access Rule for Storage Accounts is Set to Deny
                if storage_account.public_network_access:
                    print(f"\t> Vulnerability: The Storage Account '{storage_account.name}' is allowing public traffic.")
                    sentences2.append(f"\t4. Vulnerability: The Storage Account '{storage_account.name}' is allowing public traffic.")
                    sentences3.append(f"> Vulnerability: The Storage Account '{storage_account.name}' is allowing public traffic.")
                    # details_dict["Details"].append(f"Vulnerability: The Storage Account '{storage_account.name}' is allowing public traffic.")
                    details_dict["Details"][f"Vulnerability - The Storage Account '{storage_account.name}' is allowing public traffic."] = storage_account.name
                else:
                    #print(f"\t4. The Storage Account '{storage_account.name}' has denied the public traffic.")
                    sentences2.append(f"\t4. The Storage Account '{storage_account.name}' has denied the public traffic.")
                    # details_dict["Details"].append(f"The Storage Account '{storage_account.name}' has denied the public traffic.")
                    details_dict["Details"][f"The Storage Account '{storage_account.name}' has denied the public traffic."] = storage_account.name

                #Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2"
                if not storage_account.minimum_tls_version == 'TLS1_2':
                    print(f"\t> Warning: The Storage Account '{storage_account.name}' uses an outdated TLS version ({storage_account.minimum_tls_version}). Update to TLS Version 1.2 for enhanced security.")
                    sentences2.append(f"\t5. Warning: The Storage Account '{storage_account.name}' uses an outdated TLS version ({storage_account.minimum_tls_version}). Update to TLS Version 1.2 for enhanced security.")
                    sentences3.append(f"> Warning: The Storage Account '{storage_account.name}' uses an outdated TLS version ({storage_account.minimum_tls_version}). Update to TLS Version 1.2 for enhanced security.")
                    # details_dict["Details"].append(f"Warning: The Storage Account '{storage_account.name}' uses an outdated TLS version ({storage_account.minimum_tls_version}). Update to TLS Version 1.2 for enhanced security.")
                    details_dict["Details"][f"Warning - The Storage Account '{storage_account.name}' uses an outdated TLS version "] = storage_account.minimum_tls_version 
                else:
                    #print(f"\t5. TLS version for The Storage Account '{storage_account.name}' is up to date: {storage_account.minimum_tls_version}.")
                    sentences2.append(f"\t5. TLS version for The Storage Account '{storage_account.name}' is up to date: {storage_account.minimum_tls_version}.")
                    # details_dict["Details"].append(f"TLS version for The Storage Account '{storage_account.name}' is up to date: {storage_account.minimum_tls_version}.")
                    details_dict["Details"][f"TLS version for The Storage Account '{storage_account.name}' is up to date "] = storage_account.minimum_tls_version

                # sentences2.append(f"\n")
                # sentences3.append(f"\n")# After every storage account
                # details_dict["Details"].append(f"\n")

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
        # details_dict["Details"].append(f"Error Detecting Vulnerabilities For Storage Account in subscription {subscription_id}: {e}")
        # details_dict["Details"].append(f"Please ensure that the 'Storage Blob Data Reader' role is assigned to the subscription.")

    for sub in subscriptions:
        if sub.subscription_id == subscription_id:
            print(f"\nSubscription Name: {sub.display_name}")
            sentences1.append(f"\nSubscription Name: {sub.display_name}")
            sentences1.append(f"Subscription ID: {sub.subscription_id}")

            print(f"\tTotal Storage Accounts Checked: ", total_checks)
            sentences1.append(f"\nTotal Storage Accounts Checked: {total_checks}")

            print(f"\tDetected Vulnerable Storage Accounts: ", detected_count)
            sentences1.append(f"Detected Vulnerable Storage Accounts: {detected_count} \n")

            print(f"-" * 120)
            #print("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")
            
            # Add details_dict to sentences1 list
            details_dict["Subscription Name"] = sub.display_name
            details_dict["Subscription ID"] = sub.subscription_id
            details_dict["Total Storage Accounts Checked"] = total_checks
            details_dict["Total Detected Storage Accounts"] = detected_count
        #Call the save to csv function for html report
        # storageacc_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2)
        storageacc_sentences1and3_save_to_csv_for_report(csv_file_path2, datetime_now, sentences1, sentences3)
        # new_Report_Storage_Account_sentences1and2_save_to_csv_for_html_report(csv_file_path3, datetime_now, details_dict)
        json_report(json_path, datetime_now, details_dict)

if __name__ == '__main__':
    get_subscriptions()
    subscription_input = input("\nEnter the subscription ID(s) you want to check (comma-separated) or type 'all' for all subscriptions: ")

    if subscription_input.lower() == 'all':
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscription_ids = [sub.subscription_id for sub in subscription_client.subscriptions.list()]
    else:
        subscription_ids = [sub.strip() for sub in subscription_input.split(',')]

    check_storage_account_vulnerabilities(subscription_ids)