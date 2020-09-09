
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
* The user must complete the setup of the application. In order to create incident into XSOAR, a user needs to enter "Launch app" action after installing the add-on and provide the following:
    1) Create an XSOAR instance:
       Under XSOAR Instances tab, press the "Add" button. Choose an instance name, and fill the XSOAR server URL (including port if needed) and the API key fields. The API key is used for authorization with XSOAR. In order to generate this parameter, a user should log in to Demisto and then click on Settings --> Integration --> API Keys.
    2) Set up proxy settings (optional):
       Under Proxy tab, check the "Enable" checkbox and fill all the proxy parameters needed.
    3) Choose log level (optional):
       By default, the logging level is "INFO". You may change the logging level to "DEBUG" in case needed.
    4) Additional Settings (optional):
       - If you have an SSL certificate, please provide its full path under "Location to Certificate" field.
       - By default, Validate SSL is disabled. You may check it
       
# Custom Alert Action
* This application will add custom alert action named XSOAR Custom Alert Action. The user can configure this action on saved search. The user can pass following parameters to XSOAR:
    1) Name: Name of the alert.
    2) Occurred Time: Time when alert was triggered
    3) Type: Type in XSOAR.
    4) Labels: Comma separated values to be put in the label field.
    5) Severity: Severity of the alert
    6) Details: Details field in the incident.

# Troubleshooting
* Environment variable SPLUNK_HOME must be set.
* To troubleshoot Demisto add-on, check $SPLUNK_HOME/var/log/splunk/create_xsoar_incident_modalert.log file.

# Support
Customers can file issues by logging into XSOAR support portal (https://support.demisto.com).
Documentation on our support process is available in the support portal. 
