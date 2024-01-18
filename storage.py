import datetime
from datetime import datetime
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
    detected_vulnerabilities = []

    # Save results to a CSV file for all storage accounts
    csv_file_path = "temp_report_4.csv"
    with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Checking Storage Accounts Vulnerabilities"])
        writer.writerow(['Date Time', 'Vulnerability Name', 'Total Checks', 'Vulnerabilities', 'Detected Count'])

        # Use Azure SDK with managed identity
        credential = DefaultAzureCredential()

        for subscription_id in subscription_ids:
            try:
                subscription_client = SubscriptionClient(credential)
                storage_client = StorageManagementClient(credential, subscription_id)
                storage_accounts = storage_client.storage_accounts.list()

                for storage_account in storage_accounts:
                    total_checks += 1
                    account_url = f"https://{storage_account.name}.blob.core.windows.net"
                    blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
                    containers = blob_service_client.list_containers()
                    vulnerable_containers = []

                    for container in containers:
                        container_client = blob_service_client.get_container_client(container.name)
                        if is_container_public(container_client):
                            print(f"\tThe container {container.name} in storage account {storage_account.name} is public.")
                            detected_count += 1
                            detected_vulnerabilities.append(container.name)
                            vulnerable_containers.append(container.name)
                        else:
                            print(f"\tThe container {container.name} in storage account {storage_account.name} is not public.")

                    vulnerability_count = dict(Counter(vulnerable_containers))

                    for vulnerability, count in vulnerability_count.items():
                        writer.writerow([datetime.now(), "Vulnerability Detection in Storage Accounts", count, ', '.join([v for v in vulnerable_containers if v == vulnerability]), detected_count])

            except Exception as e:
                print(f"Error processing subscription {subscription_id}: {e}")
                print("Please ensure that the 'Storage Blob Data Reader' role is assigned to the subscription.")

    print("\tTotal Storage Accounts Checked: ", total_checks)
    print("\tDetected Vulnerable Storage Accounts: ", detected_count)

def is_container_public(container_client):
    try:
        container_properties = container_client.get_container_properties()
        return container_properties['public_access'] == 'blob'
    except Exception as e:
        print(f"Error checking container: {e}")
        return False

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
