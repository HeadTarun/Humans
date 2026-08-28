import streamlit as st
import requests
import json
import pandas as pd

API_URL = "http://localhost:8000/api/v1/emails/analyze"

st.set_page_config(page_title="Email Parser Tester", layout="wide")

st.title("📧 Email Parser Verification App")
st.markdown("Upload an `.eml` file to test the FastAPI email ingestion layer.")

uploaded_file = st.file_uploader("Choose an .eml file", type=["eml"])

if uploaded_file is not None:
    st.info("File uploaded successfully! Parsing via backend...")
    
    # Call the FastAPI endpoint
    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "message/rfc822")}
    
    try:
        with st.spinner("Analyzing..."):
            response = requests.post(API_URL, files=files)
            
        if response.status_code == 200:
            st.success("Parsed Successfully!")
            parsed_data = response.json()
            
            # --- OVERVIEW ---
            st.header("1. Overview")
            headers = parsed_data.get("headers", {})
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Subject:**", headers.get("subject"))
                st.write("**From:**", headers.get("from_address"))
                st.write("**From Domain:**", headers.get("from_domain"))
            with col2:
                st.write("**Message ID:**", parsed_data.get("message_id"))
                st.write("**Date:**", headers.get("date"))
                st.write("**SHA256:**", parsed_data.get("sha256"))
                
            # --- RAW HEADERS ---
            with st.expander("Raw Headers", expanded=False):
                st.json(headers.get("raw_headers", {}))
                
            # --- RECEIVED HOPS ---
            st.header("2. Received Hops")
            hops = headers.get("received_hops", [])
            if hops:
                df_hops = pd.DataFrame(hops)
                st.dataframe(df_hops, use_container_width=True)
            else:
                st.write("No received hops found.")

            # --- BODY ---
            st.header("3. Email Body")
            tab1, tab2 = st.tabs(["Plain Text", "HTML"])
            
            with tab1:
                plain_text = parsed_data.get("plain_text")
                if plain_text:
                    st.text_area("Plain Text Content", plain_text, height=300)
                else:
                    st.info("No plain text body found.")
                    
            with tab2:
                html_text = parsed_data.get("html")
                if html_text:
                    st.components.v1.html(html_text, height=400, scrolling=True)
                else:
                    st.info("No HTML body found.")
                    
            # --- URLS ---
            st.header("4. Extracted URLs")
            urls = parsed_data.get("urls", [])
            if urls:
                st.write(f"Found {len(urls)} URLs:")
                for url in urls:
                    st.write(f"- `{url}`")
            else:
                st.write("No URLs found.")

            # --- ATTACHMENTS ---
            st.header("5. Attachments")
            attachments = parsed_data.get("attachments", [])
            if attachments:
                df_atts = pd.DataFrame(attachments)
                st.dataframe(df_atts, use_container_width=True)
            else:
                st.write("No attachments found.")

            # --- FULL JSON ---
            with st.expander("View Full JSON Response"):
                st.json(parsed_data)

        else:
            st.error(f"Error from API: {response.status_code}")
            st.json(response.json())
            
    except requests.exceptions.ConnectionError:
        st.error("Connection Error: Is the FastAPI backend running on http://localhost:8000?")
        st.info("Run `uvicorn app.main:app --reload` in the `backend/` folder to start the API.")
