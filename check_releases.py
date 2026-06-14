import os
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

# The open-source GitHub tool feeds you want to monitor
FEEDS = {
    "Prometheus": "https://github.com/prometheus/prometheus/releases.atom",
    "ArgoCD": "https://github.com/argoproj/argo-cd/releases.atom",
    "Trivy": "https://github.com/aquasecurity/trivy/releases.atom",
    "Checkov": "https://github.com/bridgecrewio/checkov/releases.atom",
    "Semgrep": "https://github.com/semgrep/semgrep/releases.atom"
}

KEYWORDS = ["security", "cve", "fix", "vulnerability", "patch", "advisory"]

def check_feeds():
    alert_items = []
    now = datetime.now(timezone.utc)
    one_day_ago = now - timedelta(days=1)

    for tool, url in FEEDS.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                continue
            
            root = ET.fromstring(response.content)
            ns = {'atom': 'http://www.w3.org/2005/Atom'}
            
            for entry in root.findall('atom:entry', ns):
                title = entry.find('atom:title', ns).text
                updated_str = entry.find('atom:updated', ns).text
                content_elem = entry.find('atom:content', ns)
                content = content_elem.text if content_elem is not None else ""
                link_elem = entry.find('atom:link', ns)
                link = link_elem.attrib.get('href', '') if link_elem is not None else ''
                
                updated_time = datetime.fromisoformat(updated_str.replace('Z', '+00:00'))
                
                if updated_time > one_day_ago:
                    combined_text = (title + " " + content).lower()
                    if any(kw in combined_text for kw in KEYWORDS):
                        alert_items.append({
                            "tool": tool,
                            "title": title,
                            "link": link
                        })
        except Exception as e:
            print(f"Error checking {tool}: {e}")

    if alert_items:
        send_slack_alert(alert_items)

def send_slack_alert(items):
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("Slack Webhook URL missing.")
        return

    blocks = [{
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "🚨 Critical DevSecOps/SRE Tool Alerts"
        }
    }]
    
    for item in items:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Tool:* {item['tool']}\n*Release:* `{item['title']}`\n<{item['link']}|View Release Notes>"
            }
        })
        blocks.append({"type": "divider"})

    response = requests.post(webhook_url, json={"blocks": blocks}, timeout=10)
    print(f"Slack response: {response.status_code}")

if __name__ == "__main__":
    check_feeds()
