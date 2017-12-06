[demisto]
param._cam = <json>
	* Json specification for classifying response actions.
    * Used in AR.
    * For more information refer Appendix A of Splunk_SA_CIM.
    * Defaults to None.

param.incident_name = <string>
	* Field defines name of the Incident in Demisto
	* Defaults to "Incident from AR"

param.occured = <int>
	*EPOCH time when the alert was created.
	*Defaults to $trigger_time$

param.type = <string>
	*Type of incident in Demisto
	*Defaults to "default"

param.labels = <string>
	*Comma separted key value pair of strings to be put in Label field of Demisto
	*e.g IP:1.1.1.1,Type:Trojan
	*Defaults to blank

param.custom_field = <string>
	*Comma separted key value pair of strings to be put in Custom fields of Demisto
	*e.g KillChain:1.1.1.1,Type:Trojan
	*Defaults to blank

param.ignore_labels = <string>
	*Comma separted column names which won't be pushed to demisto when no label is set.
	*e.g User,Type
	*Defaults to blank
	
param.investigate = <int>
	*Indicates if investigation should be created in Demisto. 
	*Takes either 1 or 0 
	*Defaults to 0
param.severity = <float>
	*Drop down to define severity of the incident in Demisto
	*Can take one of the following values 0: Unknown, 1: Low, 2: Medium, 3: High, 4: Critical
	*Defaults to 0.
param.details = <string>
    * Details field in Demisto..
    * Defaults to blank

param.verbose         = <bool>
   * Set modular alert action logger to verbose mode
   * Defaults to "false"


