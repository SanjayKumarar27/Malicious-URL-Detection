import streamlit as st
import transformers
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re
import pandas as pd
import time
import matplotlib.pyplot as plt
import seaborn as sns
import requests

# Disable the warning
st.set_option('deprecation.showPyplotGlobalUse', False)

# Class for URL pattern recognition
class url_pattern_recognition:
    def __init__(self, url_pipe):
        self.url_pipeline = url_pipe

    @classmethod
    def load_model(cls, url_pattern_model="JeswinMS4/URL_DETECTION"):
        url_model = AutoModelForSequenceClassification.from_pretrained(url_pattern_model)
        url_tokenizer = AutoTokenizer.from_pretrained(url_pattern_model)
        url_pipe = transformers.pipeline("text-classification", model=url_model, tokenizer=url_tokenizer)
        return cls(url_pipe)

    def __call__(self, input_text):
        url_detect = self.url_pipeline(input_text)
        return url_detect

# Function to validate URL format
def validate_url(url):
    url_regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(url_regex, url) is not None

# Function to categorize URLs
def categorize_url(url):
    categories = {
        "Social Media": ["facebook.com", "twitter.com", "instagram.com"],
        "News": ["nytimes.com", "bbc.com", "cnn.com"],
        "Shopping": ["amazon.com", "ebay.com", "alibaba.com"],
        # Add more categories and patterns as needed
    }
    for category, patterns in categories.items():
        if any(pattern in url for pattern in patterns):
            return category
    return "Other"

# Function to check URL status
def check_url_status(url):
    try:
        response = requests.head(url)
        return response.status_code == 200
    except Exception as e:
        print(e)
        return False

# Main function for Streamlit app
def main():
    st.title("Malign/Benign URL Detection")

    # Load the URL detection model
    model = url_pattern_recognition.load_model()

    # Initialize URL history log
    if 'url_history' not in st.session_state:
        st.session_state.url_history = []

    # Input box for the URL
    input_url = st.text_input("Enter URL:", "")

    # URL Expiry Time
    expiry_time = st.number_input("Set URL Expiry Time (minutes, 0 for no expiry):", min_value=0, step=1)

    if st.button("Detect"):
        if input_url:
            if validate_url(input_url):
                # Detect URL pattern
                predictions = model(input_url)
                category = categorize_url(input_url)
                for prediction in predictions:
                    label = prediction["label"]
                    score = prediction["score"]
                    timestamp = time.time()
                    st.session_state.url_history.append({
                        "URL": input_url,
                        "Label": label,
                        "Score": score,
                        "Category": category,
                        "Timestamp": timestamp,
                        "Expiry": expiry_time
                    })
                    if label == 'BENIGN':
                        st.success(f"Label: {label}, Score: {score}")
                    else:
                        st.error(f"Label: {label}, Score: {score}")
            else:
                st.warning("Please enter a valid URL")
        else:
            st.warning("Please enter a URL")

    # Real-time URL monitoring
    if st.session_state.url_history:
        for url_info in st.session_state.url_history:
            url = url_info["URL"]
            if url_info["Expiry"] > 0:
                if (time.time() - url_info["Timestamp"]) < url_info["Expiry"] * 60:
                    url_status = "Active"
                else:
                    url_status = "Expired"
            else:
                url_status = "No Expiry"
            st.write(f"URL: {url}, Status: {url_status}")
            # Check status if not expired
            if url_status != "Expired":
                status = check_url_status(url)
                if status:
                    st.write("Status: Active")
                else:
                    st.write("Status: Inactive")

    # Filter expired URLs
    current_time = time.time()
    st.session_state.url_history = [url for url in st.session_state.url_history if url['Expiry'] == 0 or (current_time - url['Timestamp']) < url['Expiry'] * 60]

    # Display URL history
    if st.session_state.url_history:
        st.subheader("URL History")
        url_history_df = pd.DataFrame(st.session_state.url_history)
        st.dataframe(url_history_df)

        # Download URL history as CSV
        csv = url_history_df.to_csv(index=False)
        st.download_button(
            label="Download URL History as CSV",
            data=csv,
            file_name='url_history.csv',
            mime='text/csv',
        )
        # URL Categorization Visualization with Different Colors for Different Categories
        st.subheader("URL Categorization")
        category_counts = url_history_df['Label'].value_counts()
        fig, ax = plt.subplots()
        sns.barplot(x=category_counts.index, y=category_counts.values, ax=ax, palette='Set3')  # You can choose any palette you prefer
        ax.set_xticklabels(ax.get_xticklabels(), rotation=45)
        ax.set_xlabel("Category")
        ax.set_ylabel("Count")
        ax.set_title("URL Categorization")
        st.pyplot(fig)

        # Download URL history as JSON
        json = url_history_df.to_json(orient='records')
        st.download_button(
            label="Download URL History as JSON",
            data=json,
            file_name='url_history.json',
            mime='application/json',
        )

if __name__ == "__main__":
    main()
