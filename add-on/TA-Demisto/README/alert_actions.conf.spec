
[create_xsoar_incident]
python.version = python3
param.incident_name = <string> Incident Name.  It's default value is Event from Splunk for host $result.host$.
param.occurred = <string> Time Occurred (epoch).  It's default value is $trigger_time$.
param.send_all_servers = <Checkbox> Whether or not to send the alert to all servers.  It's default value is false.
param.xsoar_server = <list> XSOAR Server.
param.type = <string> Type.  It's default value is Unclassified.
param.custom_fields = <string> Custom Fields.
param.labels = <string> Labels.
param.ignore_labels = <string> Ignore Labels.
param.severity = <list> Severity.  It's default value is 0.
param.details = <string> Details.  It's default value is Incident created from Splunk to XSOAR.
param._cam = <json> Json specification for classifying response actions.
