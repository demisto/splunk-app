
# ABOUT THIS APP

Supporting Add-on for Demisto. This application allows a user to create incident into Demisto from Splunk using custom alert action.


# REQUIREMENTS

* Splunk version 6.3 >=
* This application should be installed on Search Head.

# Recommended System configuration
* Standard Splunk configuration of Search Head.

# Installation in Splunk Cloud
* Same as on-premise setup.

# Installation of App

* This app can be installed through UI using "Manage Apps" or from the command line using the following command:
$SPLUNK_HOME/bin/splunk install app $PATH_TO_SPL/TA-Demisto.spl/

# HTTPS Certificate Validation

The add-on uses secure communication with Demisto.

On few occasions it would be necessary to manually set a certificate for proper verification.

There are several options for adding a self-signed certificate or a certificate from internal certificate signers AFTER
installing the app:

1) Put the PEM formatted certificate bundle inside Splunk server under:
$SPLUNK_HOME/etc/apps/TA-Demisto/local/cert_bundle.pem

2) Add the certificate to the app installation tgz:
    2.1) Extract TA-Demisto tgz
    2.2) Create "local" directory under TA-Demisto
    2.3) Place the certificate in that folder
    In the end the certificate should be in the following path:
    your-local-path/TA-Demisto/local/cert_bundle.pem

Splunk Cloud users should perform option 2 and send the app installer to Splunk support for installation.

Another option which applies ONLY for on-prem installations and is cannot be used for Splunk Cloud:

Disabling the certificate validation entirely by POSTing to the Splunk REST API
https://splunk-server:8089/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv
with the following as the request body:
verify_ssl=false

For example, via CURL:
curl -ku 'username:password' https://localhost:8089/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/ -d VALIDATE_SSL=false

To re-enable certificate validation post to the same endpoint but change "verify_ssl" to true.

For example, via CURL:
curl -ku 'username:password' https://localhost:8089/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/ -d VALIDATE_SSL=true

We recommend to use certificates, and only disabling certificate verification in development
or test environments only. Never disable certificate verification for a production system.

* User can directly extract the app's SPL file into $SPLUNK_HOME/etc/apps/ folder in order to install the app.

# Application Setup
* The user must complete the setup of the application. In order to create incident into Demisto, a user needs to provide following four parameters:
    1)Demisto URL: This is mandatory parameter Url /IP address of the Demisto
    2)Demisto Port: This is an optional parameter. The user must define it if running Demisto on any other port than the default (443).
    3)HTTPS Proxy Address: This is an optional parameter. Define this if you have HTTPS proxy that should be used
    4)Allow Self Signed Certificate: User should select this if using Self Signed certificate
    5)Authentication key: This is a mandatory parameter. This parameter is used for authorization with Demisto. In order to generate this parameter,
      a user should log in to Demisto and then click on Settings --> Integration --> API Keys.

* Proxies should be entered in the following manner : http://username:password@ip:port

# Custom Alert Action
* This application will add custom alert action named Demisto Custom Alert Action. The user can configure this action on saved search. The user can pass following parameters to Demisto:
    1) Name: Name of the alert.
    2) Occurred Time: Time when alert was triggered
    3) Type: Type in demisto.
    4) Labels: Comma separated values to be put in the label field.
    5) Severity: Severity of the alert
    6) Details: Details field in the incident.

#Troubleshooting
* Environment variable SPLUNK_HOME must be set
* Check the following logs to troubleshoot Demisto's application:
    1) $SPLUNK_HOME/var/log/demisto/demisto.log file
    2) $SPLUNK_HOME/var/log/splunk/demisto_modalert.log
* If you change the app's settings several times in a row you might need to restart Splunk for them to update

#Support
Customers can file issues by logging into Demisto support portal (https://support.demisto.com).
Documentation on our support process is available in the support portal. 
