
import import_declare_test

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    MultipleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
import logging

util.remove_http_proxy_env_vars()


fields_proxy = [
    field.RestField(
        'proxy_enabled',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'proxy_type',
        required=False,
        encrypted=False,
        default='http',
        validator=None
    ), 
    field.RestField(
        'proxy_url',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=4096, 
            min_len=0, 
        )
    ), 
    field.RestField(
        'proxy_port',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.Number(
            max_val=65535, 
            min_val=1, 
        )
    ), 
    field.RestField(
        'proxy_username',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=50, 
            min_len=0, 
        )
    ), 
    field.RestField(
        'proxy_password',
        required=False,
        encrypted=True,
        default=None,
        validator=validator.String(
            max_len=8192, 
            min_len=0, 
        )
    ), 
    field.RestField(
        'proxy_rdns',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    )
]
model_proxy = RestModel(fields_proxy, name='proxy')


fields_logging = [
    field.RestField(
        'loglevel',
        required=True,
        encrypted=False,
        default='INFO',
        validator=validator.Pattern(
            regex=r"""^DEBUG|INFO|WARNING|ERROR|CRITICAL$""", 
        )
    )
]
model_logging = RestModel(fields_logging, name='logging')


fields_additional_parameters = [
    field.RestField(
        'ssl_cert_loc',
        required=False,
        encrypted=False,
        default='',
        validator=validator.String(
            max_len=8192, 
            min_len=0, 
        )
    ), 
    field.RestField(
        'validate_ssl',
        required=False,
        encrypted=False,
        default=1,
        validator=None
    ), 
    field.RestField(
        'timeout_val',
        required=False,
        encrypted=False,
        default='10',
        validator=validator.String(
            max_len=8192, 
            min_len=0, 
        )
    )
]
model_additional_parameters = RestModel(fields_additional_parameters, name='additional_parameters')


endpoint = MultipleModel(
    'ta_demisto_settings',
    models=[
        model_proxy, 
        model_logging, 
        model_additional_parameters
    ],
    need_reload=False,
)


if __name__ == '__main__':
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )
