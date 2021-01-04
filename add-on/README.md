# Demisto Add-on for Splunk
Supporting Add-on for Cortex XSOAR. This application allows a user to create incident into XSOAR from Splunk using custom alert action.


# Requirements
* Splunk version 7.2 >=

# Procedure for Using the Demisto Add-on in Splunk

1. [Prepare a local Splunk Environment](#prepare-a-local-splunk-environment)
2. [Installation](#installation-of-the-add-on)
3. [Configuration](#configuration)
4. [Connectivity Test](#connectivity-test-create-a-custom-alert-action)
5. [About Add-on Builder, AppInspect and Compatibility](#about-add-on-builder-appinspect-and-compatibility)
6. [Tips for Developers](#tips-for-developers)
7. [Common Issues - SSL Certificates](#common-issues-ssl-certificates)

# Prepare a local Splunk Environment
Run the following command to create a Splunk docker container (replace the `*****` with any 8-character password, containing letters and digits):
```
docker run -d -p "8000:8000" -p "8088:8088" -p "8089:8089" -e "SPLUNK_START_ARGS=--accept-license" -e "SPLUNK_PASSWORD=*****" --name splunk splunk/splunk:latest
```
Once executed, the splunk env will be available at http://localhost:8000.

# Installation of the add-on
* Download Demisto Add-on for Splunk from [Splunkbase](https://splunkbase.splunk.com/app/3448).
* After initializing the container, open your local Splunk environment.
* Go to “Manage Apps” → Install app from file → upload the latest version of Demisto Add-on for Splunk.
  *Note:* if a version of the app already exists, mark the “Upgrade app” checkbox.
  
  ![install](https://user-images.githubusercontent.com/38749041/103541256-db406b80-4ea3-11eb-9280-279f50e447f6.gif)
* Restart Splunk and login again.


# Configuration
* In order to use the add-on and create incidents in XSOAR, you must complete the setup of the application. Press "Launch app" action after installing the add-on and provide the following:
    1) Create a XSOAR instance:
       Under XSOAR Instances tab, press the "Add" button. Choose an instance name, and fill the XSOAR server URL (including port if needed) and the API key fields. The API key is used for authorization with XSOAR. In order to generate this parameter, a user should log in to Demisto and then click on Settings → Integration → API Keys.
    
       ![image](https://user-images.githubusercontent.com/38749041/103541473-25c1e800-4ea4-11eb-8868-8cad571ff58c.png)
    2) Set up proxy settings (optional):
       Under Proxy tab, check the "Enable" checkbox and fill all the proxy parameters needed.
    3) Choose log level (optional):
       By default, the logging level is "INFO". You may change the logging level to "DEBUG" if needed.
    4) Additional Settings (optional):
       - If you have an SSL certificate, please provide its full path under "Location to Certificate" field.
       - By default, "Validate SSL" is enabled.
       
       ![image](https://user-images.githubusercontent.com/38749041/103541559-4722d400-4ea4-11eb-8b01-754d9edd570c.png)
* You must restart Splunk in order to apply changes in the configuration settings.

       
# Connectivity Test - Create a Custom Alert Action
* Upload data to Splunk (any small PDF, CSV or YML file is ok).

  ![alert](https://user-images.githubusercontent.com/38749041/103539271-6d467500-4ea0-11eb-89f9-2a551893800f.gif)
* When the file is uploaded, click "Start Searching" and save the search as an Alert (on the top-right corner).
  * Complete the Alert settings:
      1. Title
      2. Permissions – Shared in App
      3. Alert type – Run on Cron Schedule
      4. Cron Expression – * * * * * (every 1 minute)
  
  * Press "Add Actions" and choose **Create XSOAR Incident**, from which you can setup the alert incident details:
      1. Name - name of the alert
      2. Time Occurred - time when alert was triggered
      3. XSOAR Server (if “Send Alert to all the servers” is unchecked)
      4. Type – incident type in XSOAR
      5. Custom Fields - A comma separated 'key:value' custom fields pairs
      6. Labels – a comma separated values to be put in the labels field
      7. Severity – the alert severity
      8. Details – “details” field of the incident

* Go to the XSOAR server and wait for incidents (one for each event in Splunk).

  ![image](https://user-images.githubusercontent.com/38749041/103539782-52c0cb80-4ea1-11eb-94a3-e284a97b33f3.png)

* *Note:* Saved Alerts can be found under Search & Reporting → Alerts.


# About Add-on Builder, AppInspect and Compatibility
* Versions 3.0.0 and above of the add-on were built using **Splunk Add-on Builder**, which simplified the latest upgrade of the add-on and the required python 2 and 3 compatibility process. Click [here](https://docs.splunk.com/Documentation/AddonBuilder/3.0.2/UserGuide/UseTheApp) to learn more about the Add-on builder.
* Splunkbase’s way to validate their apps is called **AppInspect**. Our splunk-app repository on github has a build which sends the modified version of the add-on to AppInspect.

  ![image](https://user-images.githubusercontent.com/38749041/103539976-a6cbb000-4ea1-11eb-8bcf-774262e91a0e.png)
* When bumping a version of the add-on in Splunkbase, we need to make sure it’s **compatible** with **Splunk Enterprise** and **Splunk Cloud**.

  ![image](https://user-images.githubusercontent.com/38749041/103540045-c06cf780-4ea1-11eb-9658-a559d744fa8b.png)


# Tips for Developers
1. The main python script which handles the incidents creation is found on our splunk-app repo under `add-on/TA-Demisto/bin/ta_demisto/modalert_create_xsoar_incident_helper.py`.
   An additional script is `modalert_create_xsoar_incident_utils.py` on the same directory. 
   **Any other python file shouldn’t be touched** unless we need to modify the configuration parameters.
   
   **Useful links to learn more about splunk add-ons structure:**
   - App Directory Structure: https://dev.splunk.com/enterprise/docs/developapps/createapps/appdirectorystructure/
   - Configuration Files: https://docs.splunk.com/Documentation/Splunk/8.1.0/Admin/Aboutconfigurationfiles
   - Splexicon – the Splunk glossary: https://docs.splunk.com/Splexicon

2. In case something is not working and we are not sure what happened, we have two kinds of logs:
   - `splunkd.log` – for Splunk issues
   - `create_xsoar_incident_modalert.log` – for the add-on issues

   We can reach them from the container by typing:
   ```
   docker exec -it splunk bash
   sudo cat var/log/splunk/<log_filename>.log
   ```

3. If you need to update the add-on, make sure to do the following:

   a. Bump the add-on version when you make changes in the add-on. The version should be updated in three locations:

      - `add-on/TA-Demisto/appserver/static/js/build/globalConfig.json` (only the “version” field, and not the “apiVersion” field)
      - `add-on/TA-Demisto/default/app.conf`
      - `add-on/TA-Demisto/app.manifest`

   b. Add a compressed (.tgz) file of your version under add-on/spls path.
      To create a compressed file from your local repository, run the following command on the root directory (replace xxx with new version):
      ```
      COPYFILE_DISABLE=1 tar -cvzf add-on/spls/demisto-add-on-for-splunk-xxx.tgz --exclude='*.pyc' TA-Demisto
      ```

   c. Verify AppInspect passes in the build.

   d. Upload your new version to Splunkbase (ADMINISTRATOR TOOLS → Manage app → NEW VERSION) - make sure the new version is compatible with Splunk Cloud and Splunk Enterprise.

      ![image](https://user-images.githubusercontent.com/38749041/103540137-ebefe200-4ea1-11eb-86e1-74d196988487.png)

# Common Issues - SSL Certificates
* **If you don’t use a certificate, make sure the “Validate SSL” checkbox is unmarked.**
* **If the client has a self-signed certificate, we must add it to the Splunk server first, and then set the path to it in the Add-on setup page.**
* In the case of a self-signed certificate, make sure that the **whole** certificate chain exist. If you won’t have the root, intermediate, and client certificates it won’t work (explanation about how it works can be found here).
* SSL certificates are signed on server domain rather than its IP – important as sometimes clients check validity by pinging the server IP.
