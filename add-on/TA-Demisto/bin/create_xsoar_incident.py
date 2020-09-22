
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_demisto_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_create_xsoar_incident_helper


class AlertActionWorkercreate_xsoar_incident(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkercreate_xsoar_incident, self).__init__(ta_name, alert_name)

    def validate_params(self):
        if not modalert_create_xsoar_incident_helper.get_servers_details(self):
            self.log_error('At least one server must be configured.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_create_xsoar_incident_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(str(ae)))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e:
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status


if __name__ == "__main__":
    exitcode = AlertActionWorkercreate_xsoar_incident("TA-Demisto", "create_xsoar_incident").run(sys.argv)
    sys.exit(exitcode)
