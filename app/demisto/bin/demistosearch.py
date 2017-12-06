import sys
import splunk.entity as en
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration

import os
import splunk.Intersplunk
import operator
import json
import logging
from logging.handlers import RotatingFileHandler
import splunk.version as ver
import re


version = float(re.search("(\d+.\d+)", ver.__version__).group(1))

maxbytes = 20000

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError as e:
    sys.exit(3)



def get_logger(logger_id):
    log_path = make_splunkhome_path(["var", "log", "demisto"])
    if not (os.path.isdir(log_path)):
        os.makedirs(log_path)

    handler = RotatingFileHandler(log_path + '/demisto.log', maxBytes = maxbytes,
                                  backupCount = 20)

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger = logging.getLogger(logger_id)
    logger.setLevel(logging.INFO)

    logger.addHandler(handler)
    return logger


logger = get_logger("DEMISTO_FLOOR")
@Configuration()
class demistoSearchCommand(StreamingCommand):
    """
        This Command will traverse through the raw event 
        to fetch details of search_name

        ##Syntax

        .. code-block::
        demistosearch

        ##Description

        Returns search_name information from the raw data.

        ##Example


        code-block::
            `demisto_index` sourcetype=demistoresponse | table _raw | demistosearch

    """

    def stream(self, events):
        
        data={}
        for event in events:
            raw = json.loads(event["_raw"])
            labels = raw.get("labels")
            for label in labels:
                
                if label["type"] == "search_name":
                    event["search_name"] = label["value"]
                    
                    break
            
            yield event




dispatch(demistoSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
