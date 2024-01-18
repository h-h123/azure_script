import csv
from datetime import datetime
from collections import defaultdict
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.web import WebSiteManagementClient


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


if __name__ == '__main__':
    subscriptions = get_subscriptions()
    subscription_input = input(f"\nEnter the subscription ID(s) you want to check (comma-separated) or type 'all' for all subscriptions: ")

    if subscription_input.lower() == 'all':
        subscription_ids = [sub.subscription_id for sub in subscriptions]
    else:
        subscription_ids = [sub.strip() for sub in subscription_input.split(',')]

    check_web_app(subscription_ids)


