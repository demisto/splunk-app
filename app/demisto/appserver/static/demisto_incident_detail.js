// Translations for en_US
i18n_register({
    "plural": function (n) {
        return n == 1 ? 0 : 1;
    },
    "catalog": {}
});

require(['jquery', 'underscore', 'splunkjs/mvc', 'splunkjs/mvc/tokenutils', 'splunkjs/mvc/tableview', 'splunkjs/mvc/simplexml/ready!'],
    function ($, _, mvc, tokenutils,tableview) {

        //Get Submitted Tokens
        var submittedTokens = mvc.Components.get('submitted');        
       
        // Override category token
        var severityToken = mvc.Components.get('severity_id');

        function make_severity_token(model, selectedCategories) {
            if (typeof (selectedCategories) === 'string') selectedCategories = [selectedCategories];

            if (!selectedCategories) return;
            var valuePrefix = severityToken.settings.get('valuePrefix') || '';
            var valueSuffix = severityToken.settings.get('valueSuffix') || '';
            var prefix = severityToken.settings.get('prefix') || '';
            var suffix = severityToken.settings.get('suffix') || '';
            var delimiter = severityToken.settings.get('delimiter') || '';

            selectedCategories = _(selectedCategories).filter(function (item) {
                return (item && item != '')
            });
            var newValue = _(selectedCategories).map(function (item) {
                return valuePrefix + item + valueSuffix
            });
            var severity = prefix + newValue.join(delimiter) + suffix;
            //console.log('SET', category);
            submittedTokens.set('severity', severity);
        }

        submittedTokens.on('change:form.severity_form', make_severity_token);
        make_severity_token(submittedTokens, submittedTokens.get('form.severity_form'));

        //Saved search Name
        // Override category token
        var savedSearchNameToken = mvc.Components.get('savedsearch_id');

        function make_savedsearch_token(model, savedSearchNames) {
            if (typeof (savedSearchNames) === 'string') savedSearchNames = [savedSearchNames];

            if (!savedSearchNames) return;
            var valuePrefix = savedSearchNameToken.settings.get('valuePrefix') || '';
            var valueSuffix = savedSearchNameToken.settings.get('valueSuffix') || '';
            var prefix = savedSearchNameToken.settings.get('prefix') || '';
            var suffix = savedSearchNameToken.settings.get('suffix') || '';
            var delimiter = savedSearchNameToken.settings.get('delimiter') || '';

            savedSearchNames = _(savedSearchNames).filter(function (item) {
                return (item && item != '')
            });
            var newValue = _(savedSearchNames).map(function (item) {
                return valuePrefix + item + valueSuffix
            });
            var savedsearchname = prefix + newValue.join(delimiter) + suffix;
            console.log('SavedSerachNames', savedsearchname);
            submittedTokens.set('savedsearch_name', savedsearchname);
        }

        submittedTokens.on('change:form.savedsearch_name_form', make_savedsearch_token);
        make_savedsearch_token(submittedTokens, submittedTokens.get('form.savedsearch_name_form'));
        
        
        //To handle orig_sid and orig_rid from the IR page
        function make_search_token(model, sid) {
            
            orig_rid = submittedTokens.get('form.orig_rid')
            if (typeof (sid) === 'string' && typeof(orig_rid) === 'string')
            {
                console.log(sid);
                var query= "sid = \""+sid+"\" orig_rid =\""+orig_rid + "\"";
                
            }   submittedTokens.set('investigation_form', query);


        }

        submittedTokens.on('change:form.orig_sid', make_search_token);
        make_search_token(submittedTokens, submittedTokens.get('form.orig_sid'));
        


    });