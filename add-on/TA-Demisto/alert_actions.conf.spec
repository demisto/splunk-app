
[create_xsoar_incident]
python.version = python3
param.incident_name = <string> Name.  It's default value is Event from Splunk for host $result.host$.
param.occurred = <string> Time Occurred (epoch).
param.send_all_servers = <list> Send Alert to all the Servers.  It's default value is no.
param.server_url = <list> XSOAR Server.
param.type = <string> Type.
param.custom_fields = <string> Custom Fields.
param.labels = <string> Labels.
param.ignore_labels = <string> Ignore Labels.
param.severity = <list> Severity.  It's default value is 0.
param.details = <string> Details.  It's default value is Incident created from data available in Splunk.

