[<stanza name>]
## The following attributes extend savedsearches.conf for swimlanes definitions
## Each collection should be assigned a unique integer per view "<n>"

## The per-view collection name
display.page.<view_name>.<n>.collection_name = <string>

## The per-view per-collection title of the swim lane
display.page.<view_name>.<n>.title           = <string>

## The per-view per-collection color of the swim lane
display.page.<view_name>.<n>.color           = [blue,red,orange,yellow,purple,green]

## The per-view per-collection view to forward the user to when they click the value
display.page.<view_name>.<n>.drilldown_uri   = <string>

## The per-view per-collection order of the swimlane
## This is an arbitrary integer starting at 0 (integers should not overlap)
## If group order overlaps with another swim lane they will be ordered alphanumerically
display.page.<view_name>.<n>.order           = <integer>


action.demisto = [0|1]
    * Enable stream action

action.demisto.param.incident_name = <string>
    * Name of the incident in demisto
    * Defaults to "dest_ip"

action.demisto.param.occured = <int>
    * Time when incident occured.
    * Defaults to $trigger_time$

action.demisto.param.type = <string>
    * Type of Demisto incident.
    * Defaults to blank

action.demisto.param.custom_field = <string>
    * Comma separated key-value pair to insert custom fields of demisto.

action.demisto.param.ignore_labels = <string>
    * Comma separated column names which won't be pushed to  demisto.

action.demisto.param.label = <string>
    * Comma separated key-value pair to be inserted into Label field of Incident
    * Key-value pair is separated by ":"

action.demisto.param.severity= <float>
    * Incident severity
    * Defaults to Unknown

action.demisto.param.investigate = <int>
    * Defines if investigation should be created for the incident in Demisto. Can have either 0|1  
    * Defaults to 0

action.demisto.param.details = <string>
    * Details column in Demisto Incident 

action.demisto.param.server_url = <string>
    * The Demisto server to send the alert to
    * Defaults to blank

action.demisto.param.send_all_servers = <bool>
    * Send alert to all of installed Demisto's servers
    * Defaults to false