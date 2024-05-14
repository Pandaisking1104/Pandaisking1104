import re
import requests
import numpy as np
import dns.resolver
import pandas as pd
import seaborn as sns
import networkx as nx
import whois
from datetime import datetime
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from xgboost import XGBClassifier
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split

# Function to extract features from the URL
def extract_features(url, threshold=365):
    parsed_url = urlparse(url)
    features = {}
    domain = parsed_url.netloc.split('/')[0]  # Extract domain from netloc

    features['UsingIP'] = 1 if parsed_url.netloc.isdigit() else -1
    features['LongURL'] = 1 if len(url) > 75 else 0 if len(url) > 54 else -1
    features['ShortURL'] = 1 if len(url) < 54 else -1
    features['Symbol@'] = 1 if '@' in url else -1
    features['Redirecting//'] = 1 if '//' in parsed_url.path else -1
    features['PrefixSuffix-'] = 1 if '-' in parsed_url.netloc else -1
    features['SubDomains'] = 1 if parsed_url.netloc.count('.') > 0 else -1
    features['HTTPS'] = 1 if parsed_url.scheme == 'https' else 0 if parsed_url.scheme == 'http' else -1
    features['DomainRegLen'] = extract_domain_registration_length(domain, threshold)
    features['Favicon'] = extract_favicon(url)
    features['NonStdPort'] = 1 if parsed_url.port and parsed_url.port not in [80, 443] else -1
    features['HTTPSDomainURL'] = 1 if parsed_url.scheme == 'https' else -1
    features['RequestURL'] = 1 if parsed_url.path.endswith('.exe') or parsed_url.path.endswith('.zip') else -1
    features['AnchorURL'] = 1 if parsed_url.fragment else -1 if parsed_url.fragment == '' else 0
    features['LinksInScriptTags'] = extract_links_in_script_tags(url)
    features['ServerFormHandler'] = extract_server_form_handler(url)
    features['InfoEmail'] = 1 if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', url) else -1
    features['AbnormalURL'] = is_abnormal_url(url)
    features['WebsiteForwarding'] = is_website_forwarding(url)
    features['StatusBarCust'] = StatusBarCust(url)
    features['DisableRightClick'] = has_disable_right_click(url)
    features['UsingPopupWindow'] = uses_popup_window(url)
    features['IframeRedirection'] = check_iframe_redirection(url)
    features['DNSRecording'] = detect_dns_recording(parsed_url.netloc)
    features['WebsiteTraffic'] = get_website_traffic(url)
    features['PageRank'] = get_page_rank(url, 0.5)
    features['GoogleIndex'] = is_indexed_by_google(url)
    features['LinksPointingToPage'] = count_links_pointing_to_page(url)


    return pd.DataFrame([features])

# Function to extract domain registration length
def extract_domain_registration_length(domain, threshold):
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            registration_length = (datetime.now() - creation_date).days
            if registration_length > threshold:
                return 1  # Safe
            else:
                return -1  # Phishing
        else:
            return -1  # Phishing
    except Exception as e:
        print("Error extracting domain registration length:", e)
        return -1  # Phishing

# Function to extract favicon
def extract_favicon(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check if the webpage contains a reference to a favicon file
        favicon_link = soup.find('link', rel='shortcut icon')
        if favicon_link is not None:
            return 1  # Safe
        else:
            return -1  # Suspicious or phishing
    except Exception as e:
        print("Error fetching favicon:", e)
        return -1  # Suspicious or phishing

# Function to extract links in script tags
def extract_links_in_script_tags(url):
    try:
        # Fetch the HTML content of the webpage
        response = requests.get(url)
        html_content = response.text

        # Parse the HTML content
        soup = BeautifulSoup(html_content, 'html.parser')

        # Find all <script> tags
        script_tags = soup.find_all('script')

        # Check if any links are found within <script> tags
        links_found = any(script_tag.find('a') for script_tag in script_tags)

        # Return 1 if links are found, -1 if phishing, or 0 if none are found (suspicious)
        return 1 if links_found else -1
    except Exception as e:
        print(f"Error extracting links in script tags: {e}")
        return -1  # Return -1 to indicate an error occurred during extraction

# Function to extract server form handler
def extract_server_form_handler(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all form tags
        form_tags = soup.find_all('form')

        # Check if the webpage contains any form tags
        if form_tags:
            return 1  # Return 1 if form tags are found (safe)
        else:
            return -1  # Return -1 if no form tags are found (phishing)
    except Exception as e:
        print("Error extracting server form handler:", e)
        return -1  # Return -1 to indicate an error occurred during extraction

# Function to check abnormal URL features
def is_abnormal_url(url):
    try:
        # Check for uncommon characters
        uncommon_characters = ['%', '!', '$']
        for char in uncommon_characters:
            if char in url:
                return -1

        # Check for URL encoding abuse
        if url.count('%') > 3:
            return -1

        # Check for long random strings
        if len(url.split('/')[-1]) > 30:  # Adjust the threshold as needed
            return -1

        # Check for misleading subdomains
        if any(subdomain in urlparse(url).netloc for subdomain in ['www', 'secure', 'login', 'admin']):
            return -1

        # Check for IP address instead of domain name
        if re.match(r'^\d+\.\d+\.\d+\.\d+', urlparse(url).netloc):
            return -1

        # Check for excessive subdomains or subdirectory levels
        if urlparse(url).netloc.count('.') > 5 or url.count('/') > 5:
            return -1

        # Check for phishing-like features
        phishing_keywords = ['login', 'account', 'password']
        if any(keyword in url for keyword in phishing_keywords):
            return -1

        return 1  # Return 1 if URL is normal
    except Exception as e:
        print("Error checking for abnormal URL:", e)
        return -1  # Return -1 to indicate an error occurred during processing

# Function to check website forwarding
def is_website_forwarding(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302]:
            return 1  # Return 1 if the URL is forwarding
        else:
            return 0  # Return 0 if the URL is not forwarding
    except Exception as e:
        print("Error checking for website forwarding:", e)
        return 0  # Return 0 if an error occurs (assuming non-forwarding)

# Function to check disable right-click
def has_disable_right_click(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Search for scripts that may disable right-click
        scripts = soup.find_all('script')
        for script in scripts:
            script_text = script.get_text()
            if 'event.button == 2' in script_text or 'event.button == 3' in script_text:
                return -1

        return 1  # Return 1 if no script is found disabling right-click
    except Exception as e:
        print("Error checking for disable right-click:", e)
        return 1  # Return 1 instead of -1 in case of an error

# Function to check popup window usage
def uses_popup_window(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check if the webpage contains a script for opening a popup window
        popup_script = soup.find('script', string=re.compile(r'window.open'))
        if popup_script:
            return 1
        else:
            return -1  # Return -1 if no popup window script is found
    except Exception as e:
        print("Error checking for popup window:", e)
        return -1  # Return -1 in case of an error

# Function to check iframe redirection
def check_iframe_redirection(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all iframes in the webpage
        iframes = soup.find_all('iframe')

        # Check if the number of iframes is greater than 1
        if len(iframes) > 1:
            return -1
        else:
            return 1
    except Exception as e:
        print("Error checking iframe redirection:", e)
        return -1

# Function to detect DNS recording
def detect_dns_recording(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        # If DNS records are found, return 1
        return 1
    except dns.resolver.NoAnswer:
        # No DNS records found for the domain
        return -1
    except dns.resolver.NXDOMAIN:
        # Domain does not exist
        return -1
    except Exception as e:
        # Other errors
        return -1

# Function to fetch website traffic
def get_website_traffic(url):
    try:
        api_key = '0oa147y669ev1NXyJ358'
        response = requests.get(f"https://quantcast.com/api/v1/traffic/{url}", headers={'Authorization': f'Api-Key {api_key}'})
        if response.status_code == 200:
            data = response.json()
            total_visits = data.get('total_visits', -1)
            return 1 if total_visits > 0 else 0
        else:
            return -1
    except Exception as e:
        print("Error fetching website traffic:", e)
        return -1

# Function to get PageRank
def get_page_rank(url, threshold=0.5):
    try:
        graph = nx.DiGraph()
        graph.add_node(url)

        pr = nx.pagerank(graph)

        if pr[url] >= threshold:
            return 1  # Safe
        else:
            return -1  # Phishing
    except nx.NetworkXError as e:
        print("NetworkX Error:", e)
        return -1
    except Exception as e:
        print("Error getting PageRank:", e)
        return -1

# Function to check if indexed by Google
def is_indexed_by_google(url):
    from googleapiclient.discovery import build
    try:
        api_key = 'AIzaSyCgOTLbOqXWPwsnAkmZhpxPy--1f0VdV8w'
        cx = '900fa7f60ea254754'
        service = build("customsearch", "v1", developerKey=api_key)

        search_query = f'site:{url}'
        res = service.cse().list(q=search_query, cx=cx).execute()

        if 'items' in res:
            return 1  # URL is indexed by Google
        else:
            return -1  # URL is not indexed by Google
    except Exception as e:
        print(f"Error checking Google index: {e}")
        return -1  # Return a default value to indicate error

# Function to count links pointing to the page
def count_links_pointing_to_page(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all <a> tags
        links = soup.find_all('a')

        # Count the number of links pointing to the page
        num_links_pointing_to_page = sum(1 for link in links if link.get('href') == url)

        # Return 1 if at least one link points to the page, 0 if no links point to the page, -1 if an error occurs
        if num_links_pointing_to_page > 0:
            return 1  # Safe
        elif num_links_pointing_to_page == 0:
            return 0  # Suspicious
        else:
            return -1  # Phishing or error
    except Exception as e:
        print("Error occurred:", e)
        return -1  # Phishing or error

# Function to check for status bar customization
def StatusBarCust(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            html_content = response.text

            # Updated regular expression pattern to handle potential escape errors
            status_bar_pattern = r'onmouseover\s*=\s*"window\.status\s*=\s*\'(.+?)\'"'
            matches = re.findall(status_bar_pattern, html_content)

            if matches:
                # Status bar customization detected
                return -1  # Phishing
            else:
                # No status bar customization detected
                return 1  # Safe
        else:
            # Failed to fetch webpage
            return -1  # Phishing or error
    except Exception as e:
        # Error occurred during execution
        return -1  # Phishing or error

# Function to generate statistics report
def Stats_Report(features_df):
    try:
        stats = {}
        for column in features_df.columns:
            if features_df[column].nunique() == 1:
                stats[column] = 1  # Unique value
            else:
                stats[column] = -1  # Non-unique value
        return stats
    except Exception as e:
        print("Error occurred:", e)
        return -1

# Main function to predict phishing
def predict_phishing(features_df):
    try:
        data = pd.read_csv('phishing.csv')
        data = data.drop(['Index'], axis=1)
        X = data.drop(["class","AgeofDomain","StatsReport"], axis=1)
        y = data["class"]
        
        # Map -1 to 0 in the target variable y
        y = y.replace(-1, 0)

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        xgb = XGBClassifier()
        
        xgb.fit(X_train, y_train)
        
        ans = xgb.predict(features_df)
        
        if -1 in ans:
            return 'Phishing'
        else:
            return 'Safe'
    except Exception as e:
        print("Error predicting phishing:", e)
        return "Error"

# Function to generate pie chart
def pichart():
    try:
        data = pd.read_csv('phishing.csv')
        data['class'].value_counts().plot(kind='pie',autopct='%1.2f%%')
        plt.title("Phishing Count")
        plt.savefig('pie_chart.jpg')
    except Exception as e:
        print("Error generating pie chart:", e)

# Function to generate heatmap
def heatmap():
    try:
        data = pd.read_csv('phishing.csv')
        plt.figure(figsize=(15, 15))
        sns.heatmap(data.corr(), annot=True)
        plt.savefig('heatmap.jpg')
    except Exception as e:
        print("Error generating heatmap:", e)

if __name__ == "__main__":    
    url = input('Enter url: ')
    features_df = extract_features(url)
    prediction = predict_phishing(features_df)
    print("Prediction:", prediction)
