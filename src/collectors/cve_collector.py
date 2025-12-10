import requests
import json
from datetime import datetime, timedelta, timezone

class CVECollector:
    """
    A class to collect Common Vulnerabilities and Exposures (CVEs) from the NIST NVD API.
    """
    def __init__(self, api_url="https://services.nvd.nist.gov/rest/json/cves/2.0"):
        """
        Initializes the CVECollector with the API URL.

        :param api_url: The URL of the NIST NVD CVE API.
        """
        self.api_url = api_url

    def fetch_recent_cves(self, days_back=7):
        """
        Fetches recent CVEs from the NIST NVD API.

        :param days_back: The number of days back from today to fetch CVEs for.
        :return: A list of dictionaries, where each dictionary represents a parsed CVE.
        """
        print("[+] Fetching recent CVEs...")
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days_back)

        # ISO 8601 format with UTC timezone info
        start_date_iso = start_date.isoformat().replace('+00:00', 'Z')
        end_date_iso = end_date.isoformat().replace('+00:00', 'Z')

        params = {
            'pubStartDate': start_date_iso,
            'pubEndDate': end_date_iso
        }

        try:
            response = requests.get(self.api_url, params=params)
            response.raise_for_status()  # Raise an exception for bad status codes
            raw_data = response.json()

            # Extract and parse the relevant data
            parsed_cves = []
            for vulnerability in raw_data.get('vulnerabilities', []):
                cve_item = vulnerability.get('cve', {})
                cve_id = cve_item.get('id')
                # Descriptions are often provided in a list, we'll take the first English one
                description = next((desc['value'] for desc in cve_item.get('descriptions', []) if desc.get('lang') == 'en'), "No description available.")
                published_date = cve_item.get('published')
                vuln_status = cve_item.get('vulnStatus')

                parsed_cves.append({
                    'cve_id': cve_id,
                    'description': description,
                    'published_date': published_date,
                    'vuln_status': vuln_status
                })
            print(f"[+] Found {len(parsed_cves)} CVEs.")
            return parsed_cves

        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching data: {e}")
            return None

    def save_to_file(self, data):
        """
        Saves the given data to a JSON file in the 'data/' directory.

        :param data: The data to save (expected to be a list of dictionaries).
        """
        if not data:
            print("[!] No data to save.")
            return

        today_str = datetime.now().strftime('%Y%m%d')
        filename = f"data/cves_{today_str}.json"

        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"[+] Data saved to {filename}")
        except IOError as e:
            print(f"[!] Error saving data to file: {e}")

if __name__ == "__main__":
    collector = CVECollector()
    recent_cves = collector.fetch_recent_cves(days_back=7)
    if recent_cves:
        collector.save_to_file(recent_cves)
