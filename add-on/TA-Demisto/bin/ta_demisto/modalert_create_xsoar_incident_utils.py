import time


def get_incident_labels(helper, event, labels_str, ignore_labels, search_query=None, search_name=None, search_url=None):
    # if labels parameter is not empty, gets only the specified labels.
    # otherwise, gets all the non-ignored labels from Splunk event.
    labels = [
        {'type': 'SplunkSearch', 'value': search_query},
        {'type': 'SplunkURL', 'value': search_url}
    ]

    if search_name:
        labels.append({'type': 'search_name', 'value': search_name})

    if ignore_labels:
        ignore_labels = ignore_labels.strip().lower().split(',')

    helper.log_info('Labels::::{}'.format(list(event.keys())))
    helper.log_info('Ignored Labels::::{}'.format(ignore_labels))

    if labels_str:
        labels_str = labels_str.strip().split(',')
        for data_label in labels_str:
            param_data = data_label.split(':')
            labels.append({
                'type': param_data[0],
                'value': ':'.join(param_data[1:])
            })
    else:
        for key in list(event.keys()):
            if (not ignore_labels or key.lower() not in ignore_labels) and not key.startswith('__'):
                labels.append({
                    'type': key,
                    'value': event[key]
                })
    return labels


def get_incident_custom_fields(custom_fields_str):
    str_data = split_fields(custom_fields_str.strip())
    custom_fields = {}
    for data in str_data:
        param_data = data.split(':')
        custom_fields[param_data[0]] = ':'.join(param_data[1:])
    return custom_fields


def split_fields(s):
    """ Splits the custom fields string, and takes in count commas which are part of the field value.
    For example, a possible value for s:
        "key1:\"val,with,commas\",key2:`val2,with,commas`,key3:(val,3),key4:val4a:val4b"
    Expected result would be:
        ["key1:\"val,with,commas\"", "key2:`val2,with,commas`", "key3:(val,3)", "key4:val4a:val4b"]

    :param s: the custom fields string input
    :return: a key:value list of the custom fields.
    """

    result = []
    if s is None or len(s) == 0:
        return result

    arr = s.split(',')
    temp = ''
    for item in arr:
        temp += item.strip()
        if ':' in temp and temp.count('"') % 2 == 0 and temp.count('`') % 2 == 0 and temp.count("'") % 2 == 0 \
                and temp.count("(") == temp.count(")") and temp.count("{") == temp.count("}"):
            result.append(temp)
            temp = ''
        elif ':' not in temp:
            if len(result) == 0:
                result.append(temp)
            else:
                result[-1] += (',' + temp)
            temp = ''
        else:
            temp += ','
    return result


def get_incident_occurred_field(occurred):
    zone = time.strftime('%z')
    timezone = zone[-5:][:3] + ':' + zone[-5:][3:]
    occurred = int(float(occurred))
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(occurred)) + timezone
