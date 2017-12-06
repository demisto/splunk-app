[<stanza name>]
   * Create a unique stanza name for each post process search.
   * Follow the stanza name with any number of the following attribute/value pairs.
   * If you do not specify an attribute, Splunk uses the default.

disabled = [0|1]
   * Disable your search by setting to 1.
   * If set to 1, this saved search is not visible in Splunk Web.
   * Defaults to 0.

savedsearch = <string>
    * Name of saved search to post process.
    * Must match stanza in savedsearches.conf.
    * savedSearch must be scheduled.
    * savedSearch must specify action.postprocess = 1.

postprocess = <string>
    * Actual search terms of the saved search.
    * For example, postProcess = stats count by host.
    * Your search can include macro searches for substitution.
    * To learn more about creating a macro search, search the documentation for "macro search."