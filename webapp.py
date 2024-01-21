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

#######################################################################################################

def webapp_sentences1and2_save_to_csv_for_html_report(csv_file_path, datetime_now, sentences1, sentences2):
    fieldnames = ["Date Time"]
    with open(csv_file_path, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Detecting Vulnerabilities in Web Apps ...\n"])
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
        writer.writerow(["Detecting Vulnerabilities in Web Apps ...\n"])
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
    csv_file_path = "azure_web_app_HTML_report.csv"
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
                        print(f"\n\t> Vulnerability: App Service Authentication Disabled for WebApp '{web_app.name}'")
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
                    #     print(f"\t> Vulnerability: Azure Active Directory (AAD) Claims Authorization for WebApp '{web_app.name}' is not configured.")
                    #     sentences2.append(f"\t> Vulnerability: Azure Active Directory (AAD) Claims Authorization for WebApp '{web_app.name}' is not configured.")
                    #     sentences3.append(f"> Vulnerability: Azure Active Directory (AAD) Claims Authorization for WebApp '{web_app.name}' is not configured.")
                    # else:
                    #     print(f"\t> Azure Active Directory (AAD) Claims Authorization Status for the WebApp '{web_app.name}' is configured with '{auth_settings.aad_claims_authorization}'")
                    #     sentences2.append(f"\t> Azure Active Directory (AAD) Claims Authorization Status for the WebApp '{web_app.name}' is configured with '{auth_settings.aad_claims_authorization}'")

                    if auth_settings.unauthenticated_client_action == 'AllowAnonymous':
                        print(f"\t> Vulnerability: Unauthenticated Client Action for WebApp '{web_app.name}' is set to Allow Anonymous")
                        sentences2.append(f"\t> Vulnerability: Unauthenticated Client Action for WebApp '{web_app.name}' is set to Allow Anonymous")
                        sentences3.append(f"> Vulnerability: Unauthenticated Client Action for WebApp '{web_app.name}' is set to Allow Anonymous")
                    else:
                        #print(f"\t> Unauthenticated Client Action for WebApp '{web_app.name}' is not set to Allow Anonymous")
                        sentences2.append(f"\t> Unauthenticated Client Action for WebApp '{web_app.name}' is not set to Allow Anonymous")

                    if not web_app_configuration.auto_heal_enabled:
                        print(f"\t> Warning: If auto-healing is disabled, WebApp '{web_app.name}' might not recover automatically from failures, leading to potential downtime.")
                        sentences2.append(f"\t> Warning: If auto-healing is disabled, WebApp '{web_app.name}' might not recover automatically from failures, leading to potential downtime.")
                        sentences3.append(f"> Warning: If auto-healing is disabled, WebApp '{web_app.name}' might not recover automatically from failures, leading to potential downtime.")
                    else:
                        #print(f"\t> Autoheal feature is enabled for WebApp '{web_app.name}'")
                        sentences2.append(f"\t> Autoheal feature is enabled for WebApp '{web_app.name}'")

                    # if  web_app_configuration.http_logging_enabled:
                    #     print(f"\t> Warning: If HTTP logging is disabled, it may hinder the ability to monitor and troubleshoot issues for WebApp '{web_app.name}'.")
                        # sentences2.append(f"\t> Warning: If HTTP logging is disabled, it may hinder the ability to monitor and troubleshoot issues for WebApp '{web_app.name}'.")
                        # sentences3.append(f"5. > Warning: If HTTP logging is disabled, it may hinder the ability to monitor and troubleshoot issues for WebApp '{web_app.name}'.")
                    # else:
                    #     print(f"\t> HTTP logging is enabled for WebApp '{web_app.name}'")
                        # sentences2.append(f"\t> HTTP logging is enabled for WebApp '{web_app.name}'")

                    if not web_app_configuration.http20_enabled:
                        print(f"\t> Warning: HTTP2.0 is disabled for WebApp '{web_app.name}', it may impact the performance benefits provided by the protocol.")
                        sentences2.append(f"\t> Warning: HTTP2.0 is disabled for WebApp '{web_app.name}', it may impact the performance benefits provided by the protocol.")
                        sentences3.append(f"> Warning: HTTP2.0 is disabled for WebApp '{web_app.name}', it may impact the performance benefits provided by the protocol.")
                    else:
                        #print(f"\t> HTTP2.0 is Enabled for WebApp '{web_app.name}'")
                        sentences2.append(f"\t> HTTP2.0 is Enabled for WebApp '{web_app.name}'")

                    if not float(web_app_configuration.min_tls_version) <= 1.2:
                        print(f"\t> Warning: The TLS (Transport Layer Security) protocol for WebApp '{web_app.name}' secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS.")
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
                        print(f"\t> Vulnerability: Enabling public network access may expose the WebApp '{web_app.name}' to potential external threats.")
                        sentences2.append(f"\t> Vulnerability: Enabling public network access may expose the WebApp '{web_app.name}' to potential external threats.")
                        sentences3.append(f"> Vulnerability: Enabling public network access may expose the WebApp '{web_app.name}' to potential external threats.")
                    else:
                        #print(f"\t> Public Network access is disabled to the WebApp '{web_app.name}'")
                        sentences2.append(f"\t> Public Network access is disabled to the WebApp '{web_app.name}'")

                    if web_app_configuration.managed_service_identity_id is None:
                        print(f"\t> Vulnerability: Managed Service Identity not configured for WebApp '{web_app.name}', leaving it potentially insecure.")
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


if __name__ == '__main__':
    subscriptions = get_subscriptions()
    subscription_input = input(f"\nEnter the subscription ID(s) you want to check (comma-separated) or type 'all' for all subscriptions: ")

    if subscription_input.lower() == 'all':
        subscription_ids = [sub.subscription_id for sub in subscriptions]
    else:
        subscription_ids = [sub.strip() for sub in subscription_input.split(',')]

    check_web_app(subscription_ids)


