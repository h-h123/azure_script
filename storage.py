import datetime
import csv
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


def check_storage_account_vulnerabilities(subscription_ids):
    print(f"\nDetecting Vulnerabilities in Storage Accounts...")
    total_checks = 0
    detected_count = 0

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

                # Ensure that 'Secure transfer required' is set to 'Enabled'
                if not storage_account.enable_https_traffic_only:
                    print(f"\n\t1. Vunerability: The Storage Account {storage_account.name} has not enforced Secure transfer (HTTPS).")
                else:
                    print(f"\n\t1. The Storage Account {storage_account.name} has enforced Secure transfer (HTTPS).")
                
                #Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’
                if not storage_account.encryption.require_infrastructure_encryption:
                    print(f"\t2. Vunerability: The Storage Account {storage_account.name} has not enabled Infrastructure Encryption.")
                else:
                    print(f"\t2. The Storage Account {storage_account.name} has enabled Infrastructure Encryption.")

                #Ensure that 'Public access level' is disabled for storage accounts with blob containers 
                if storage_account.allow_blob_public_access:
                    print(f"\t3. Vulnerability : The Storage Account {storage_account.name} with blob containers has allowed public access")
                else:
                    print(f"\t3. The Storage Account {storage_account.name} with blob containers has denied public access")

                ## Ensure Default Network Access Rule for Storage Accounts is Set to Deny
                if storage_account.public_network_access:
                    print(f"\t4. Vulnerabilty: The Storage Account {storage_account.name} is allowing public traffic.")
                else:
                    print(f"\t4. The Storage Account {storage_account.name} has denied the public traffic")

                #Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2"
                if not storage_account.minimum_tls_version == 'TLS1_2':
                    print(f"\t5. Warning: The TLS (Transport Layer Security) protocol for the storage account {storage_account.name} secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. And here it is {storage_account.minimum_tls_version}")
                else:
                    print(f"\t5. TLS (Transport Layer Security) protocol version for the storage account {storage_account.name} is",storage_account.minimum_tls_version)


                if (
                    not storage_account.enable_https_traffic_only
                    or not storage_account.encryption.require_infrastructure_encryption
                    or storage_account.allow_blob_public_access
                    or storage_account.public_network_access
                ):
                    detected_count +=1



        except Exception as e:
            print(f"Error processing subscription {subscription_id}: {e}")
            print("Please ensure that the 'Storage Blob Data Reader' role is assigned to the subscription.")


        for sub in subscriptions:
            if sub.subscription_id == subscription_id:
                print(f"\nSubscription Name: {sub.display_name}")
                print("\tTotal Storage Accounts Checked: ", total_checks)
                print("\tDetected Vulnerable Storage Accounts: ", detected_count)

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
