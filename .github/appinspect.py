import requests
import time
import json
import argparse

from requests.auth import HTTPBasicAuth


class AppInspector:

    def __init__(self, username, password, spl_path):
        self.username = username
        self.password = password
        self.spl_path = spl_path
        self.token = self.get_access_token()
        self.request_id = None

    def get_access_token(self):
        auth_url = 'https://api.splunk.com/2.0/rest/login/splunk'
        response = requests.get(auth_url, auth=HTTPBasicAuth(self.username, self.password))
        response.raise_for_status()

        return response.json().get('data').get('token')

    def http_request(self, method, url, data=None, files=None, raise_errors=True):
        headers = {'Authorization': f'Bearer {self.token}'}

        response = requests.request(method, url, headers=headers, data=data, files=files)

        if raise_errors:
            response.raise_for_status()

        return response

    def submit_file(self):
        url = 'https://appinspect.splunk.com/v1/app/validate'

        files = {'app_package': open(self.spl_path, 'rb')}

        response = self.http_request('POST', url, files=files)

        self.request_id = response.json().get('request_id')

        print(f'Successfully submitted add-on to to AppInspect.\nRequest ID: {self.request_id}')

    def wait_for_submission_report(self):
        while True:
            url = f'https://appinspect.splunk.com/v1/app/validate/status/{self.request_id}'
            print('Checking if submission report is ready...')
            response = self.http_request('GET', url, raise_errors=False)

            if response.status_code == 404 or response.json().get('status') in ['PREPARING', 'PROCESSING']:
                time.sleep(5)  # report is not ready - do nothing
            elif response.status_code == 200:
                print(response.json().get('status'))
                print('Report is ready!')
                break
            else:
                response.raise_for_status()

    def get_submission_report(self):
        url = f'https://appinspect.splunk.com/v1/app/report/{self.request_id}'
        response = self.http_request('GET', url)

        response.raise_for_status()

        return response.json()

    def is_submission_valid(self, report_json):
        summary = report_json.get('summary')
        failures = summary.get('failure')

        if failures == 0:
            return True
        else:
            print(f'Inspection failed: {self.get_failures(report_json=report_json)}')
            return False

    def get_failures(self, report_json):
        failed = []
        reports = report_json.get('reports', [])

        for report in reports:
            for group in report.get('groups', []):
                for check in group.get('checks'):
                    if check.get('result') == 'failure':
                        failed.append(check)

        return json.dumps(failed, indent=4, sort_keys=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Splunk AppInspect')
    parser.add_argument('username', type=str, help='Username')
    parser.add_argument('password', type=str, help='Password')
    parser.add_argument('spl_path', type=str, help='SPL Path')
    args = parser.parse_args()

    inspector = AppInspector(args.username, args.password, args.spl_path)

    inspector.submit_file()
    inspector.wait_for_submission_report()

    report = inspector.get_submission_report()
    if inspector.is_submission_valid(report_json=report):
        print('AppInspect PASSED!')
    else:
        raise Exception('AppInspect FAILED!')
