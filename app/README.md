# ABOUT THIS APP

Demisto App for Splunk helps in tracking Splunk to Demisto incident creation.

# REQUIREMENTS

* Splunk version 6.3 >=

# Recommended System configuration

* Splunk forwarder system should have 4 GB of RAM and a quad-core CPU to run this app smoothly.


# Topology and Setting up Splunk Environment


* This app has been distributed in two parts.

  1) Add-on app, which helps in creating incident into Demisto
  2) Main app for visualizing Splunk to Demisto Integration.

* This App setup is same for  both distributed and standalone environment:

     * Configure Add-on app on Search head.
     * Install the Main app on search head.


# Installation in Splunk Cloud

* It is same as on-premise Splunk.


# Installation of App

* This app can be installed through UI using "Manage Apps" or extract zip file directly into /opt/splunk/etc/apps/ folder.

# TEST YOUR INSTALL

The main app dashboard can take some time before the data is returned which will populate some of the panels. A good test is to run following query

    search `demisto_get_index` source = demisto

If you don't see these sourcetypes, run following query to find out if any alert with demisto action was executed.
     index="_internal" source = *scheduler*  alert_actions="demisto"

#Support
Customers can file issues by logging into Demisto support portal (https://support.demisto.com).
Documentation on our support process is available in the support portal.