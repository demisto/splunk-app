
# ABOUT THIS APP

Supporting Add-on for XSOAR. This application allows a user to create incident into XSOAR from Splunk using custom alert action.


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


* User can directly extract SPL file  into $SPLUNK_HOME/etc/apps/ folder.


# Application Setup
* The user must complete the setup of the application. In order to create incident into Demisto, a user needs to provide following four parameters:
    1)Demisto URL: This is mandatory parameter Url /IP address of the Demisto
    2)Demisto Port: This is an optional parameter. The user must define it if running Demisto on any other port than the default (443).
    3)Allow Self Signed Certificate: User should select this if using Self Signed certificate
    4) Authentication key: This is a mandatory parameter. This parameter is used for authorization with Demsito. In order to generate this parameter, a user should log in to Demisto and then click on Settings --> Integration --> API Keys.

# Custom Alert Action
* This application will add custom alert action named Demisto Custom Alert Action. The user can configure this action on saved search. The user can pass following parameters to Demisto:
    1) Name: Name of the alert.
    2) Occurred Time: Time when alert was triggered
    3) Type: Type in demisto.
    4) Labels: Comma separated values to be put in the label field.
    5) Severity: Severity of the alert
    6) Details: Details field in the incident.

# Troubleshooting
* Environment variable SPLUNK_HOME must be set
* To troubleshoot Demisto application, check $SPLUNK_HOME/var/log/splunk/demisto.log file.

# Support
Customers can file issues by logging into Demisto support portal (https://support.demisto.com).
Documentation on our support process is available in the support portal. 
