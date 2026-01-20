#!/usr/bin/env python3
"""
Persistence Finder - Web Viewer
Beautiful web interface to view and analyze persistence scan results
"""

import streamlit as st
import json
import os
import glob
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Page configuration
st.set_page_config(
    page_title="Persistence Finder - Scan Results",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .warning-box {
        background-color: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ffc107;
    }
    .danger-box {
        background-color: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #dc3545;
    }
    .success-box {
        background-color: #d4edda;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #28a745;
    }
</style>
""", unsafe_allow_html=True)

def load_scan_files():
    """Load all scan JSON files from scans directory"""
    scan_dirs = ['scans', os.path.expanduser('~/persistent-finder-scans')]
    scan_files = []
    
    for scan_dir in scan_dirs:
        if os.path.exists(scan_dir):
            files = glob.glob(os.path.join(scan_dir, "scan_*.json"))
            scan_files.extend(files)
    
    scan_files.sort(reverse=True)  # Most recent first
    return scan_files

def load_scan_data(filepath):
    """Load scan data from JSON file"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        st.error(f"Error loading scan file: {e}")
        return None

def parse_timestamp(ts_str):
    """Parse timestamp string to datetime"""
    try:
        return datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
    except:
        return None

def filter_by_date(items, start_date, end_date):
    """Filter items by modification date"""
    filtered = {}
    
    for key, value in items.items():
        if isinstance(value, dict):
            # Check if it has a modified timestamp
            if 'modified' in value:
                mod_time = parse_timestamp(value['modified'])
                if mod_time and start_date <= mod_time.date() <= end_date:
                    filtered[key] = value
            elif any('modified' in str(v) for v in value.values() if isinstance(v, dict)):
                # Nested structure with timestamps
                filtered[key] = value
        elif isinstance(value, list):
            # List of items with timestamps
            filtered_list = []
            for item in value:
                if isinstance(item, dict) and 'modified' in item:
                    mod_time = parse_timestamp(item['modified'])
                    if mod_time and start_date <= mod_time.date() <= end_date:
                        filtered_list.append(item)
            if filtered_list:
                filtered[key] = filtered_list
    
    return filtered

def display_scan_overview(scan_data, scan_metadata):
    """Display scan overview with metrics"""
    st.markdown('<h1 class="main-header">🔍 Persistence Finder - Scan Results</h1>', unsafe_allow_html=True)
    
    # Scan metadata
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Platform", scan_metadata.get('platform', 'Unknown').upper())
    with col2:
        st.metric("Scan Time", scan_metadata.get('scan_time', 'Unknown'))
    with col3:
        st.metric("Total Categories", len(scan_data))
    with col4:
        total_findings = sum(len(v) if isinstance(v, (list, dict)) else 1 for v in scan_data.values() if v)
        st.metric("Total Findings", total_findings)
    
    # System info
    if 'system_info' in scan_metadata:
        with st.expander("📊 System Information", expanded=False):
            sys_info = scan_metadata['system_info']
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Architecture:** {sys_info.get('architecture', 'N/A')}")
                st.write(f"**Python Version:** {sys_info.get('python_version', 'N/A')}")
                st.write(f"**Admin/Root:** {'✅ Yes' if sys_info.get('is_admin') else '❌ No'}")
            with col2:
                if 'linux_name' in sys_info:
                    st.write(f"**Distribution:** {sys_info.get('linux_name', 'N/A')}")
                    st.write(f"**Version:** {sys_info.get('linux_version', 'N/A')}")
                    st.write(f"**Kernel:** {sys_info.get('kernel', 'N/A')}")

def create_timeline_chart(scan_data):
    """Create timeline visualization of modifications"""
    timeline_data = []
    
    for category, items in scan_data.items():
        if isinstance(items, dict):
            for key, value in items.items():
                if isinstance(value, dict) and 'modified' in value:
                    mod_time = parse_timestamp(value['modified'])
                    if mod_time:
                        timeline_data.append({
                            'Category': category,
                            'Item': key.split('/')[-1][:50],
                            'Modified': mod_time,
                            'Full_Path': key
                        })
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and 'modified' in item:
                            mod_time = parse_timestamp(item['modified'])
                            if mod_time:
                                timeline_data.append({
                                    'Category': category,
                                    'Item': item.get('name', 'Unknown')[:50],
                                    'Modified': mod_time,
                                    'Full_Path': item.get('name', 'Unknown')
                                })
    
    if timeline_data:
        df = pd.DataFrame(timeline_data)
        df = df.sort_values('Modified', ascending=False)
        
        fig = px.scatter(df, x='Modified', y='Category', 
                        hover_data=['Item', 'Full_Path'],
                        title='Modification Timeline',
                        color='Category',
                        height=400)
        fig.update_traces(marker=dict(size=10))
        st.plotly_chart(fig, use_container_width=True)
        
        return df
    return None

def create_category_chart(scan_data):
    """Create category distribution chart"""
    category_counts = {}
    
    for category, items in scan_data.items():
        if items:
            if isinstance(items, list):
                category_counts[category] = len(items)
            elif isinstance(items, dict):
                category_counts[category] = len(items)
            else:
                category_counts[category] = 1
    
    if category_counts:
        df = pd.DataFrame(list(category_counts.items()), columns=['Category', 'Count'])
        df = df.sort_values('Count', ascending=True)
        
        fig = px.bar(df, x='Count', y='Category', orientation='h',
                    title='Findings by Category',
                    color='Count',
                    color_continuous_scale='Blues')
        st.plotly_chart(fig, use_container_width=True)

def display_category_details(category_name, items, date_filter=None):
    """Display detailed view of a category"""
    st.subheader(f"📁 {category_name}")
    
    if not items:
        st.info("No items found in this category")
        return
    
    # Apply date filter if provided
    if date_filter:
        items = filter_by_date(items, date_filter[0], date_filter[1])
        if not items:
            st.warning("No items match the selected date range")
            return
    
    if isinstance(items, list):
        # Display as table if possible
        if items and isinstance(items[0], dict):
            df = pd.DataFrame(items)
            st.dataframe(df, use_container_width=True)
        else:
            for item in items:
                st.write(f"• {item}")
    
    elif isinstance(items, dict):
        # Display each item
        for key, value in items.items():
            with st.expander(f"🔹 {key.split('/')[-1]}", expanded=False):
                if isinstance(value, dict):
                    # Display as key-value pairs
                    for k, v in value.items():
                        if k == 'modified':
                            st.write(f"**{k.title()}:** 🕒 {v}")
                        elif k == 'content' or k == 'content_preview':
                            st.code(v, language='bash')
                        elif isinstance(v, list):
                            st.write(f"**{k.title()}:**")
                            for item in v:
                                st.write(f"  • {item}")
                        else:
                            st.write(f"**{k.title()}:** {v}")
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            st.json(item)
                        else:
                            st.write(f"• {item}")
                else:
                    st.write(value)
    else:
        st.write(items)

def main():
    # Sidebar
    st.sidebar.title("🔍 Persistence Finder")
    st.sidebar.markdown("---")
    
    # Load available scans
    scan_files = load_scan_files()
    
    if not scan_files:
        st.error("No scan files found! Run a scan first.")
        st.info("Run: `python3 main.py` to generate scan data")
        return
    
    # Scan selection
    scan_options = [os.path.basename(f) for f in scan_files]
    selected_scan = st.sidebar.selectbox("Select Scan", scan_options)
    selected_file = scan_files[scan_options.index(selected_scan)]
    
    # Load scan data
    scan_data_full = load_scan_data(selected_file)
    if not scan_data_full:
        return
    
    scan_metadata = scan_data_full.get('metadata', {})
    scan_data = scan_data_full.get('results', {})
    
    # Date filter
    st.sidebar.markdown("---")
    st.sidebar.subheader("📅 Date Filter")
    enable_date_filter = st.sidebar.checkbox("Enable Date Filtering")
    
    date_filter = None
    if enable_date_filter:
        col1, col2 = st.sidebar.columns(2)
        with col1:
            start_date = st.date_input("From", datetime.now() - timedelta(days=30))
        with col2:
            end_date = st.date_input("To", datetime.now())
        date_filter = (start_date, end_date)
    
    # Category filter
    st.sidebar.markdown("---")
    st.sidebar.subheader("🗂️ Category Filter")
    all_categories = list(scan_data.keys())
    selected_categories = st.sidebar.multiselect(
        "Select Categories",
        all_categories,
        default=all_categories
    )
    
    # Search
    st.sidebar.markdown("---")
    search_term = st.sidebar.text_input("🔎 Search", "")
    
    # Main content
    display_scan_overview(scan_data, scan_metadata)
    
    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "📈 Timeline", "📋 Details", "📄 Raw JSON"])
    
    with tab1:
        st.header("Overview")
        create_category_chart(scan_data)
        
        # Recent modifications
        st.subheader("🕒 Recent Modifications (Last 7 Days)")
        recent_items = []
        cutoff_date = datetime.now() - timedelta(days=7)
        
        for category, items in scan_data.items():
            if isinstance(items, dict):
                for key, value in items.items():
                    if isinstance(value, dict) and 'modified' in value:
                        mod_time = parse_timestamp(value['modified'])
                        if mod_time and mod_time >= cutoff_date:
                            recent_items.append({
                                'Category': category,
                                'Item': key,
                                'Modified': value['modified']
                            })
        
        if recent_items:
            df = pd.DataFrame(recent_items)
            df = df.sort_values('Modified', ascending=False)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No modifications in the last 7 days")
    
    with tab2:
        st.header("Timeline Analysis")
        timeline_df = create_timeline_chart(scan_data)
        
        if timeline_df is not None:
            st.subheader("📊 Modification Statistics")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Items with Timestamps", len(timeline_df))
            with col2:
                oldest = timeline_df['Modified'].min()
                st.metric("Oldest Modification", oldest.strftime('%Y-%m-%d'))
            with col3:
                newest = timeline_df['Modified'].max()
                st.metric("Newest Modification", newest.strftime('%Y-%m-%d'))
    
    with tab3:
        st.header("Detailed Results")
        
        # Filter categories
        filtered_data = {k: v for k, v in scan_data.items() if k in selected_categories}
        
        # Apply search
        if search_term:
            search_filtered = {}
            for category, items in filtered_data.items():
                if search_term.lower() in category.lower():
                    search_filtered[category] = items
                elif isinstance(items, dict):
                    matching_items = {k: v for k, v in items.items() if search_term.lower() in k.lower()}
                    if matching_items:
                        search_filtered[category] = matching_items
            filtered_data = search_filtered
        
        # Display categories
        for category, items in filtered_data.items():
            if items:
                display_category_details(category, items, date_filter)
                st.markdown("---")
    
    with tab4:
        st.header("Raw JSON Data")
        st.json(scan_data_full)
        
        # Download button
        json_str = json.dumps(scan_data_full, indent=2)
        st.download_button(
            label="📥 Download JSON",
            data=json_str,
            file_name=selected_scan,
            mime="application/json"
        )
    
    # Footer
    st.sidebar.markdown("---")
    st.sidebar.info(f"📊 Viewing: {selected_scan}")
    st.sidebar.success("✅ Scan loaded successfully")

if __name__ == "__main__":
    main()
