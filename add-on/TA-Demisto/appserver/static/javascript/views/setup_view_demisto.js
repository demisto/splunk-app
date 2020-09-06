"use strict";

define(
    ["backbone", "jquery", "splunkjs/splunk"],
    function(Backbone, jquery, splunk_js_sdk) {

        var DemistoView = Backbone.View.extend({
            // -----------------------------------------------------------------
            // Backbone Functions, These are specific to the Backbone library
            // -----------------------------------------------------------------
            initialize: function initialize() {
                Backbone.View.prototype.initialize.apply(this, arguments);
            },

            events: {
                "click .setup_button": "trigger_setup",
            },

            render: function() {
                this.el.innerHTML = this.get_template();

                return this;
            },

            // -----------------------------------------------------------------
            // Custom Functions, These are unrelated to the Backbone functions
            // -----------------------------------------------------------------
            // ----------------------------------
            // Main Setup Logic
            // ----------------------------------
            // This performs some sanity checking and cleanup on the inputs that
            // the user has provided before kicking off main setup process
            trigger_setup: function trigger_setup() {
                // Used to hide the error output, when a setup is retried
                this.display_error_output([]);

                // console.log("Triggering setup");

                // create reference to form inputs
                var server_input_element = jquery("input[name=DEMISTOURL]");
                var port_input_element = jquery("input[name=PORT]");
                var api_key_input_element = jquery("input[name=AUTHKEY]");
                var cert_location_input_element = jquery("input[name=SSL_CERT_LOC]");
                var http_proxy_address_input_element = jquery("input[name=HTTPS_PROXY_ADDRESS]");
                var http_proxy_username_input_element = jquery("input[name=HTTPS_PROXY_USERNAME]");
                var http_proxy_password_input_element = jquery("input[name=HTTPS_PROXY_PASSWORD]");

                // get value of form input references
                var the_server = server_input_element.val();
                var the_port = port_input_element.val();
                var the_api_key = api_key_input_element.val();
                var the_cert = cert_location_input_element.val();
                var the_proxy_server = http_proxy_address_input_element.val();
                var the_proxy_user = http_proxy_username_input_element.val();
                var the_proxy_password = http_proxy_password_input_element.val();

                // cleanup form input values
                var sanitized_the_server = this.sanitize_string(the_server);
                var sanitized_the_port = this.sanitize_string(the_port);
                var sanitized_the_api_key = this.sanitize_string(the_api_key);
                var sanitized_the_cert = this.sanitize_string(the_cert);
                var sanitized_the_proxy_server = this.sanitize_string(the_proxy_server);
                var sanitized_the_proxy_user = this.sanitize_string(the_proxy_user);
                var sanitized_the_proxy_password = this.sanitize_string(the_proxy_password);

                // validate input values
                var error_messages_to_display = this.validate_inputs(
                    sanitized_the_server,
                    sanitized_the_port,
                    sanitized_the_api_key,
                    sanitized_the_cert,
                    sanitized_the_proxy_server,
                    sanitized_the_proxy_user,
                    sanitized_the_proxy_password,
                );

                // check for errors and update user if found
                // otherwise call setup function with cleaned input values
                var did_error_messages_occur = error_messages_to_display.length > 0;
                if (did_error_messages_occur) {
                    // Displays the errors that occurred input validation
                    this.display_error_output(error_messages_to_display);
                } else {
                    // console.log("Performing setup")
                    this.perform_setup(
                        splunk_js_sdk,
                        sanitized_the_server,
                        sanitized_the_port,
                        sanitized_the_api_key,
                        sanitized_the_cert,
                        sanitized_the_proxy_server,
                        sanitized_the_proxy_user,
                        sanitized_the_proxy_password,
                    );
                }
            },

            // This is where the main setup process occurs
            perform_setup: async function perform_setup(
                splunk_js_sdk,
                sanitized_the_server,
                sanitized_the_port,
                sanitized_the_api_key,
                sanitized_the_cert,
                sanitized_the_proxy_server,
                sanitized_the_proxy_user,
                sanitized_the_proxy_password,
            ) {
                var app_name = "TA-Demisto";

                var application_name_space = {
                    owner: "nobody",
                    app: app_name,
                    sharing: "app",
                };

                try {
                    // Create the Splunk JS SDK Service object
                    var splunk_js_sdk_service = this.create_splunk_js_sdk_service(
                        splunk_js_sdk,
                        application_name_space,
                    );

                    // Creates the custom configuration file of this Splunk- App
                    // All required information for this Splunk App is placed in
                    // there
                    await this.create_custom_configuration_file(
                        splunk_js_sdk_service,
                        sanitized_the_server,
                        sanitized_the_port,
                        sanitized_the_api_key,
                        sanitized_the_cert,
                        sanitized_the_proxy_server,
                        sanitized_the_proxy_user,
                        sanitized_the_proxy_password
                    );

                    // Creates the passwords.conf stanza that is the encrypted version
                    // of the data provided by the user
                    await this.encrypt_sensitive_data(
                        splunk_js_sdk_service,
                        sanitized_the_api_key,
                        sanitized_the_proxy_password
                    );

                    // Completes the setup, by accessing the app.conf's [install] stanza
                    // and then setting the `is_configured` to true
                    await this.complete_setup(splunk_js_sdk_service);

                    // Reloads the splunk app so that splunk is aware of the
                    // updates made to the file system
                    await this.reload_splunk_app(splunk_js_sdk_service, app_name);

                    // Redirect to the Splunk App's home page
                    this.redirect_to_splunk_homepage();
                } catch (error) {
                    // This could be better error catching.
                    // Usually, error output that is ONLY relevant to the user
                    // should be displayed. This will return output that the
                    // user does not understand, causing them to be confused.
                    var error_messages_to_display = [];
                    if (
                        error !== null &&
                        typeof error === "object" &&
                        error.hasOwnProperty("responseText")
                    ) {
                        var response_object = JSON.parse(error.responseText);
                        error_messages_to_display = this.extract_error_messages(
                            response_object.messages,
                        );
                    } else {
                        // Assumed to be string
                        error_messages_to_display.push(error);
                    }

                    this.display_error_output(error_messages_to_display);
                }
            },

            create_custom_configuration_file: async function create_custom_configuration_file(
                splunk_js_sdk_service,
                sanitized_the_server,
                sanitized_the_port,
                sanitized_the_api_key,
                sanitized_the_cert,
                sanitized_the_proxy_server,
                sanitized_the_proxy_user,
                sanitized_the_proxy_password
            ) {
                var custom_configuration_file_name = "demistosetup";

                var stanza_name_1 = "demistoenv";

                var properties_to_update_1 = {
                    DEMISTOURL: sanitized_the_server,
                    PORT: sanitized_the_port,
                    SSL_CERT_LOC: sanitized_the_cert,
                    HTTPS_PROXY_ADDRESS: sanitized_the_proxy_server,
                    HTTPS_PROXY_USERNAME: sanitized_the_proxy_user,
                    HTTPS_PROXY_PASSWORD: sanitized_the_proxy_password
                };

                await this.update_configuration_file(
                    splunk_js_sdk_service,
                    custom_configuration_file_name,
                    stanza_name_1,
                    properties_to_update_1
                );

            },

            encrypt_sensitive_data: async function encrypt_sensitive_data(
                splunk_js_sdk_service,
                sanitized_the_api_key,
                sanitized_the_proxy_password
            ) {
                // create realms for each stored password
                var sanitized_the_api_key_realm = "TA-Demisto";
                var sanitized_the_proxy_password_realm = "TA-Demisto-Proxy";
                // var username = "admin";

                var storage_passwords_accessor = splunk_js_sdk_service.storagePasswords(
                    {
                        // No namespace information provided
                    },
                );
                await storage_passwords_accessor.fetch();

                // API KEY check and write
                var check_if_api_key_exists = this.does_storage_password_exist(
                    storage_passwords_accessor,
                    sanitized_the_api_key_realm,
                    sanitized_the_api_key
                );

                var does_api_key_storage_password_exist = check_if_api_key_exists[0];
                var api_key_storage_passwords_found = check_if_api_key_exists[1];

                // If previous passwords were found, clear them all out before moving on
                if (does_api_key_storage_password_exist) {
                    // console.log("api key exists")
                    var i;
                    for (i = 0; i < api_key_storage_passwords_found.length; i++) {
                        await this.delete_storage_password(
                            storage_passwords_accessor,
                            sanitized_the_api_key_realm,
                            api_key_storage_passwords_found[i]
                        );
                    }
                } else {
                    // console.log("api key does not exist")
                }

                // PROXY PASSWORD check and write
                var check_if_proxy_password_exists = this.does_storage_password_exist(
                    storage_passwords_accessor,
                    sanitized_the_proxy_password_realm,
                    sanitized_the_proxy_password
                );

                var does_proxy_password_storage_password_exist = check_if_proxy_password_exists[0];
                var proxy_password_storage_passwords_found = check_if_proxy_password_exists[1];

                // If previous passwords were found, clear them all out before moving on
                if (does_proxy_password_storage_password_exist) {
                    // console.log("proxy password exists")
                    var i;
                    for (i = 0; i < proxy_password_storage_passwords_found.length; i++) {
                        await this.delete_storage_password(
                            storage_passwords_accessor,
                            sanitized_the_proxy_password_realm,
                            proxy_password_storage_passwords_found[i]
                        );
                    }
                } else {
                    // console.log("proxy password does not exist")
                }

                if (sanitized_the_api_key.length > 0) {
                    await this.create_storage_password_stanza(
                        storage_passwords_accessor,
                        sanitized_the_api_key_realm,
                        sanitized_the_api_key_realm.split("-").slice(-1),
                        sanitized_the_api_key,
                    );
                }
                if (sanitized_the_proxy_password.length > 0) {
                    await this.create_storage_password_stanza(
                        storage_passwords_accessor,
                        sanitized_the_proxy_password_realm,
                        sanitized_the_proxy_password_realm.split("-").slice(-1),
                        sanitized_the_proxy_password,
                    );
                }
            },

            complete_setup: async function complete_setup(splunk_js_sdk_service) {
                var app_name = "TA-Demisto";
                var configuration_file_name = "app";
                var stanza_name = "install";
                var properties_to_update = {
                    is_configured: "true",
                };

                await this.update_configuration_file(
                    splunk_js_sdk_service,
                    configuration_file_name,
                    stanza_name,
                    properties_to_update,
                );
            },

            reload_splunk_app: async function reload_splunk_app(
                splunk_js_sdk_service,
                app_name,
            ) {
                var splunk_js_sdk_apps = splunk_js_sdk_service.apps();
                await splunk_js_sdk_apps.fetch();

                var current_app = splunk_js_sdk_apps.item(app_name);
                current_app.reload();
            },

            // ----------------------------------
            // Splunk JS SDK Helpers
            // ----------------------------------
            // ---------------------
            // Process Helpers
            // ---------------------
            update_configuration_file: async function update_configuration_file(
                splunk_js_sdk_service,
                configuration_file_name,
                stanza_name,
                properties,
            ) {
                // Retrieve the accessor used to get a configuration file
                var splunk_js_sdk_service_configurations = splunk_js_sdk_service.configurations(
                    {
                        // Name space information not provided
                    },
                );
                await splunk_js_sdk_service_configurations.fetch();

                // Check for the existence of the configuration file being editect
                var does_configuration_file_exist = this.does_configuration_file_exist(
                    splunk_js_sdk_service_configurations,
                    configuration_file_name,
                );

                // If the configuration file doesn't exist, create it
                if (!does_configuration_file_exist) {
                    await this.create_configuration_file(
                        splunk_js_sdk_service_configurations,
                        configuration_file_name,
                    );
                }

                // Retrieves the configuration file accessor
                var configuration_file_accessor = this.get_configuration_file(
                    splunk_js_sdk_service_configurations,
                    configuration_file_name,
                );
                await configuration_file_accessor.fetch();

                // Checks to see if the stanza where the inputs will be
                // stored exist
                var does_stanza_exist = this.does_stanza_exist(
                    configuration_file_accessor,
                    stanza_name,
                );

                // If the configuration stanza doesn't exist, create it
                if (!does_stanza_exist) {
                    await this.create_stanza(configuration_file_accessor, stanza_name);
                }
                // Need to update the information after the creation of the stanza
                await configuration_file_accessor.fetch();

                // Retrieves the configuration stanza accessor
                var configuration_stanza_accessor = this.get_configuration_file_stanza(
                    configuration_file_accessor,
                    stanza_name,
                );
                await configuration_stanza_accessor.fetch();

                // We don't care if the stanza property does or doesn't exist
                // This is because we can use the
                // configurationStanza.update() function to create and
                // change the information of a property
                await this.update_stanza_properties(
                    configuration_stanza_accessor,
                    properties,
                );
            },

            // ---------------------
            // Existence Functions
            // ---------------------
            does_configuration_file_exist: function does_configuration_file_exist(
                configurations_accessor,
                configuration_file_name,
            ) {
                var was_configuration_file_found = false;

                var configuration_files_found = configurations_accessor.list();
                var index;
                for (index = 0; index < configuration_files_found.length; index++) {
                    var configuration_file_name_found =
                        configuration_files_found[index].name;
                    if (configuration_file_name_found === configuration_file_name) {
                        was_configuration_file_found = true;
                    }
                }

                return was_configuration_file_found;
            },

            does_stanza_exist: function does_stanza_exist(
                configuration_file_accessor,
                stanza_name,
            ) {
                var was_stanza_found = false;

                var stanzas_found = configuration_file_accessor.list();
                var index;
                for (index = 0; index < stanzas_found.length; index++) {
                    var stanza_found = stanzas_found[index].name;
                    if (stanza_found === stanza_name) {
                        was_stanza_found = true;
                    }
                }

                return was_stanza_found;
            },

            does_stanza_property_exist: function does_stanza_property_exist(
                configuration_stanza_accessor,
                property_name,
            ) {
                var was_property_found = false;

                for (const [key, value] of Object.entries(
                    configuration_stanza_accessor.properties(),
                )) {
                    if (key === property_name) {
                        was_property_found = true;
                    }
                }

                return was_property_found;
            },

            does_storage_password_exist: function does_storage_password_exist(
                storage_passwords_accessor,
                realm_name,
                username,
            ) {
                var storage_passwords = storage_passwords_accessor.list();
                var storage_passwords_found = [];
                var realm_username = realm_name + ":" + username + ":";
                var index;
                for (index = 0; index < storage_passwords.length; index++) {
                    var storage_password = storage_passwords[index];
                    var storage_password_stanza_name = storage_password.name;
                    // if (storage_password_stanza_name == realm_username) {
                    if (storage_password_stanza_name.startsWith(realm_name)) {
                        // Found password in this realm so we need to remove it before saving
                        // storage_passwords_found.push(storage_password_stanza_name);
                        storage_passwords_found.push(storage_password._state.content.username);
                    }
                }
                var does_storage_password_exist = storage_passwords_found.length > 0;

                return [does_storage_password_exist, storage_passwords_found];
            },

            // ---------------------
            // Retrieval Functions
            // ---------------------
            get_configuration_file: function get_configuration_file(
                configurations_accessor,
                configuration_file_name,
            ) {
                var configuration_file_accessor = configurations_accessor.item(
                    configuration_file_name,
                    {
                        // Name space information not provided
                    },
                );

                return configuration_file_accessor;
            },

            get_configuration_file_stanza: function get_configuration_file_stanza(
                configuration_file_accessor,
                configuration_stanza_name,
            ) {
                var configuration_stanza_accessor = configuration_file_accessor.item(
                    configuration_stanza_name,
                    {
                        // Name space information not provided
                    },
                );

                return configuration_stanza_accessor;
            },

            get_configuration_file_stanza_property: function get_configuration_file_stanza_property(
                configuration_file_accessor,
                configuration_file_name,
            ) {
                return null;
            },

            // ---------------------
            // Creation Functions
            // ---------------------
            create_splunk_js_sdk_service: function create_splunk_js_sdk_service(
                splunk_js_sdk,
                application_name_space,
            ) {
                var http = new splunk_js_sdk.SplunkWebHttp();

                var splunk_js_sdk_service = new splunk_js_sdk.Service(
                    http,
                    application_name_space,
                );

                return splunk_js_sdk_service;
            },

            create_configuration_file: function create_configuration_file(
                configurations_accessor,
                configuration_file_name,
            ) {
                var parent_context = this;

                return configurations_accessor.create(configuration_file_name, function(
                    error_response,
                    created_file,
                ) {
                    // Do nothing
                });
            },

            create_stanza: function create_stanza(
                configuration_file_accessor,
                new_stanza_name,
            ) {
                var parent_context = this;

                return configuration_file_accessor.create(new_stanza_name, function(
                    error_response,
                    created_stanza,
                ) {
                    // Do nothing
                });
            },

            update_stanza_properties: function update_stanza_properties(
                configuration_stanza_accessor,
                new_stanza_properties,
            ) {
                var parent_context = this;

                return configuration_stanza_accessor.update(
                    new_stanza_properties,
                    function(error_response, entity) {
                        // Do nothing
                    },
                );
            },

            create_storage_password_stanza: function create_storage_password_stanza(
                splunk_js_sdk_service_storage_passwords,
                realm,
                username,
                value_to_encrypt,
            ) {
                var parent_context = this;

                return splunk_js_sdk_service_storage_passwords.create(
                    {
                        name: username,
                        password: value_to_encrypt,
                        realm: realm,
                    },
                    function(error_response, response) {
                        // Do nothing
                    },
                );
            },

            // ----------------------------------
            // Deletion Methods
            // ----------------------------------
            delete_storage_password: function delete_storage_password(
                storage_passwords_accessor,
                realm,
                username,
            ) {
                try {
                    var del_status = storage_passwords_accessor.del(realm + ":" + username + ":");
                    return del_status;
                }
                catch(err) {
                    // console.log("Could not delete " + realm + ":" + username)
                    return true;
                }
            },

            // ----------------------------------
            // Input Cleaning and Checking
            // ----------------------------------
            sanitize_string: function sanitize_string(string_to_sanitize) {
                var sanitized_string = string_to_sanitize.trim();

                return sanitized_string;
            },

            validate_input: function validate_input(hostname) {
                var error_messages = [];

                var is_string_empty = typeof hostname === "undefined" || hostname === "";
                var does_string_start_with_http_protocol = hostname.startsWith("http://");
                var does_string_start_with_https_protocol = hostname.startsWith(
                    "https://",
                );

                if (is_string_empty) {
                    error_message =
                        "The `API URL` specified was empty. Please provide" + " a value.";
                    error_messages.push(error_message);
                }
                if (does_string_start_with_http_protocol) {
                    error_message =
                        "The `API URL` specified is using `http://` at the" +
                        " beginning of it. Please remove the `http://` and" +
                        " enter the url with out it in `API URL` field.";
                    error_messages.push(error_message);
                }
                if (does_string_start_with_https_protocol) {
                    error_message =
                        "The `API URL` specified is using `https://` at the" +
                        " beginning of it. Please remove the `https://` and" +
                        " enter the url with out it in `API URL` field.";
                    error_messages.push(error_message);
                }

                return error_messages;
            },

            validate_api_key_input: function validate_api_key_input(api_key) {
                var error_messages = [];

                var is_string_empty = typeof api_key === "undefined" || api_key === "";

                if (is_string_empty) {
                    error_message = "The `API Key` specified was empty. Please provide a value.";
                    error_messages.push(error_message);
                }

                return error_messages;
            },

            validate_inputs: function validate_inputs(
                sanitized_the_server,
                sanitized_the_port,
                sanitized_the_api_key,
                sanitized_the_cert,
                sanitized_the_proxy_server,
                sanitized_the_proxy_user,
                sanitized_the_proxy_password
            ) {
                var error_messages = [];

                // var api_url_errors = this.validate_api_url_input(hostname);
                // var api_key_errors = this.validate_api_key_input(api_key);

                // error_messages = error_messages.concat(api_url_errors);
                // error_messages = error_messages.concat(api_key_errors);

                return error_messages;
            },

            // ----------------------------------
            // GUI Helpers
            // ----------------------------------
            extract_error_messages: function extract_error_messages(error_messages) {
                // A helper function to extract error messages

                // Expects an array of messages
                // [
                //     {
                //         type: the_specific_error_type_found,
                //         text: the_specific_reason_for_the_error,
                //     },
                //     ...
                // ]

                var error_messages_to_display = [];
                var index;
                for (index = 0; index < error_messages.length; index++) {
                    error_message = error_messages[index];
                    error_message_to_display = error_message.type + ": " + error_message.text;
                    error_messages_to_display.push(error_message_to_display);
                }

                return error_messages_to_display;
            },

            redirect_to_splunk_homepage: function redirect_to_splunk_homepage() {

                window.location.href = "/";
            },

            // ----------------------------------
            // Display Functions
            // ----------------------------------
            display_error_output: function display_error_output(error_messages) {
                // Hides the element if no messages, shows if any messages exist
                var did_error_messages_occur = error_messages.length > 0;

                var error_output_element = jquery(".setup.container .error.output");

                if (did_error_messages_occur) {
                    var new_error_output_string = "";
                    new_error_output_string += "<ul>";
                    var index;
                    for (index = 0; index < error_messages.length; index++) {
                        new_error_output_string += "<li>" + error_messages[index] + "</li>";
                    }
                    new_error_output_string += "</ul>";

                    error_output_element.html(new_error_output_string);
                    error_output_element.stop();
                    error_output_element.fadeIn();
                } else {
                    error_output_element.stop();
                    error_output_element.fadeOut({
                        complete: function() {
                            error_output_element.html("");
                        },
                    });
                }
            },

            get_template: function get_template() {
                template_string =
                    "<div class='title'>" +
                    "    <h1>XSOAR Setup Page</h1>" +
                    "</div>" +
                    "<div class='setup container'>" +
                    "    <div class='left'>" +
                    "        <h2>XSOAR Server Config</h2>" +
                    "        <div class='field ioc_filters'>" +
                    "            <div class='title'>" +
                    "                <div>" +
                    "                    <h3>XSOAR URL/Hostname/IP Address:</h3>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='user_input'>" +
                    "                <div class='text'>" +
                    "                    <input type='text' name='DEMISTOURL' placeholder='' value=''></input>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='title'>" +
                    "                <div>" +
                    "                    <h3>XSOAR Application Port:</h3>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='user_input'>" +
                    "                <div class='text'>" +
                    "                    <input type='text' name='PORT' placeholder=''></input>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='title'>" +
                    "                <div>" +
                    "                    <h3>API Key:</h3>" +
                    "                    <h2>To generate new API key, login to Demisto application, go to Settings-->Integrations-->API Keys(Get Your Key)</h2>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='user_input'>" +
                    "                <div class='text'>" +
                    "                    <input type='text' name='AUTHKEY'></input>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='title'>" +
                    "                <div>" +
                    "                    <h3>Location to Certificate:</h3>" +
                    "                    <h2>Enter the full path to the SSL Certificate in the Splunk server to if you are using Self Signed/Internal CA signed certificate</h2>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='user_input'>" +
                    "                <div class='text'>" +
                    "                    <input type='text' name='SSL_CERT_LOC'></input>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='title'>" +
                    "                <div>" +
                    "                    <h3>(Optional) HTTPS Proxy Address:</h3>" +
                    "                    <h2>Enter HTTPS Proxy address in the following format - https://[hostname]:[port]</h2>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='user_input'>" +
                    "                <div class='text'>" +
                    "                    <input type='text' name='HTTPS_PROXY_ADDRESS'></input>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='title'>" +
                    "                <div>" +
                    "                    <h3>(Optional) HTTPS Proxy Username :</h3>" +
                    "                    <h2>Enter HTTPS Proxy Username here if applicable</h2>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='user_input'>" +
                    "                <div class='text'>" +
                    "                    <input type='text' name='HTTPS_PROXY_USERNAME'></input>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='title'>" +
                    "                <div>" +
                    "                    <h3>(Optional) HTTPS Proxy Address Password :</h3>" +
                    "                    <h2>Enter HTTPS Proxy Password here if applicable</h2>" +
                    "                </div>" +
                    "            </div>" +
                    "            <div class='user_input'>" +
                    "                <div class='text'>" +
                    "                    <input type='text' name='HTTPS_PROXY_PASSWORD'></input>" +
                    "                </div>" +
                    "            </div>" +
                    "        </div>" +
                    "        <br/>" +
                    "        <div>" +
                    "            <button name='setup_button' class='setup_button'>" +
                    "                Save" +
                    "            </button>" +
                    "        </div>" +
                    "        <br/>" +
                    "        <div class='error output'>" +
                    "        </div>" +
                    "    </div>" +
                    "</div>";

                return template_string;
            },
        }); // End of DemistoView class declaration

        return DemistoView;
    }, // End of require asynchronous module definition function
); // End of require statement
