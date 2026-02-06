import pandas as pd
import requests
import logging
from rich.console import Console
from rich.table import Table
from rich.table import Table
import datetime
import json
import os

# Configuration
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
OUTPUT_FILE = "threat_intel_feed.json"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Setup Logging
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
console = Console()

def fetch_urlhaus():
    """Fetches and parses URLhaus CSV."""
    logging.info("Fetching URLhaus data...")
    try:
        df = pd.read_csv(URLHAUS_CSV_URL, skiprows=8, header=0, skipinitialspace=True)
        # Clean and rename
        # URLhaus headers usually: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        # We need: date, ioc_value, ioc_type, threat_tag, source
        
        # Filter strictly for 'id' to ensure we have a valid row, though pandas handles this reasonably well
        if df.empty:
            logging.warning("URLhaus data is empty.")
            return pd.DataFrame()

        df['source'] = 'URLhaus'
        df['ioc_type'] = 'url'
        
        # Rename columns to match schema
        # dateadded -> date
        # url -> ioc_value
        # tags -> threat_tag (might need handling for NaNs)
        
        df.rename(columns={
            'dateadded': 'date',
            'url': 'ioc_value', 
            'tags': 'threat_tag'
        }, inplace=True)
        
        # Select and reorder
        required_cols = ['date', 'ioc_value', 'ioc_type', 'threat_tag', 'source']
        # Ensure all columns exist, fill if missing
        for col in required_cols:
            if col not in df.columns:
                df[col] = None
                
        return df[required_cols]

    except Exception as e:
        logging.error(f"Error fetching URLhaus: {e}")
        return pd.DataFrame()

def fetch_feodo():
    """Fetches and parses Feodo Tracker CSV."""
    logging.info("Fetching Feodo Tracker data...")
    try:
        # Feodo data often has comments at top. Need to handle skiprows carefully or use comment='#'
        df = pd.read_csv(FEODO_BLOCKLIST_URL, skiprows=8,  skipinitialspace=True)
        # Expected headers: first_seen_utc, dst_ip, dst_port, c2_status, last_seen_utc, malware
        
        if df.empty:
            logging.warning("Feodo Tracker data is empty.")
            return pd.DataFrame()

        df['source'] = 'FeodoTracker'
        df['ioc_type'] = 'ip:port'
        
        # Rename
        # first_seen_utc -> date
        # dst_ip -> ioc_value (Combine with port maybe? request said "standardise columns", let's keep it simple for now or combine)
        # Request said "Blocklist IP", usually just IP. But Feodo tracks C2 IPs and Ports. 
        # Let's use dst_ip as ioc_value for now, and maybe append port if needed, but IOC usually implies the observable.
        # Let's combine IP:PORT for ioc_value as that is more useful for C2.
        
        df['ioc_value'] = df['dst_ip'] + ':' + df['dst_port'].astype(str)
        df.rename(columns={'first_seen_utc': 'date', 'malware': 'threat_tag'}, inplace=True)
        
        # Enrich country if available? Feodo CSV usually doesn't have country column in standard blocklist.
        # Check https://feodotracker.abuse.ch/downloads/ipblocklist.csv content structure.
        # Actually, let's verify if 'country' is in there. 
        
        required_cols = ['date', 'ioc_value', 'ioc_type', 'threat_tag', 'source']
         # Ensure all columns exist
        for col in required_cols:
            if col not in df.columns:
                df[col] = None
        
        return df[required_cols]

    except Exception as e:
        logging.error(f"Error fetching Feodo Tracker: {e}")
        return pd.DataFrame()

def enrich_ip(df):
    """Enriches IP data with Country if possible."""
    # For now, minimal implementation. 
    # If the source provided country, we would use it. 
    # Since we are sticking to basic Pandas, we will add a placeholder or simple logic if applicable.
    if 'country' not in df.columns:
        df['country'] = 'Unknown'
    return df

def generate_report(df):
    """Generates console report using Rich."""
    if df.empty:
        console.print("[bold red]No data to report.[/bold red]")
        return

    # Top 10 Malwares (Threat Tags)
    top_threats = df['threat_tag'].value_counts().head(10)

    table = Table(title="Top 10 Malwares of the Day")
    table.add_column("Rank", justify="right", style="cyan", no_wrap=True)
    table.add_column("Malware / Tag", style="magenta")
    table.add_column("Count", justify="right", style="green")

    for idx, (tag, count) in enumerate(top_threats.items(), 1):
        table.add_row(str(idx), str(tag), str(count))

    console.print(table)
    
    # Bar Chart Visualization
    console.print() 
    console.print("[bold cyan]Top Malware Distribution[/bold cyan]")
    
    if not top_threats.empty:
        max_count = top_threats.max()
        chart_width = 50
        
        for tag, count in top_threats.items():
            # Truncate label 
            label = str(tag)
            if len(label) > 25:
                label = label[:22] + "..."
            
            # Calculate bar length
            bar_len = int((count / max_count) * chart_width)
            bar = "#" * bar_len
            
            # Print row
            # Format: Label | Bar Count
            console.print(f"{label:<26} [magenta]{bar}[/magenta] [green]{count}[/green]")
            
    console.print(f"\n[bold]Total IOCs Collected:[/bold] {len(df)}")


def save_data(df):
    """Saves consolidated data to JSON."""
    try:
        # Convert to list of dicts for JSON export, handling dates strings
        result = df.to_dict(orient='records')
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(result, f, indent=4)
        logging.info(f"Data saved to {OUTPUT_FILE}")
    except Exception as e:
        logging.error(f"Error saving data: {e}")

def main():
    console.print("[bold blue]ThreatHarvest Started...[/bold blue]")
    
    df_urlhaus = fetch_urlhaus()
    df_feodo = fetch_feodo()
    
    frames = [df_urlhaus, df_feodo]
    df_combined = pd.concat(frames, ignore_index=True)
    
    if df_combined.empty:
        logging.warning("No data collected from any source.")
    else:
        # Basic cleanup
        df_combined['date'] = pd.to_datetime(df_combined['date'], errors='coerce')
        
        # Fill NaT dates with a default low value for sorting, or drop them. 
        # Let's keep them but put them at the end.
        # Actually, let's just drop rows without a valid date if strictly needed, 
        # but better to assume current time or just handle NaT. 
        # Pandas 2.x sorts NaT to the end by default in ascending=False (or beginning?). 
        # Let's fill NaT with a dummy date for stability if needed, but NaT is usually fine if we don't mix with strings.
        
        # We need to avoiding filling NaT with 'Unknown' yet.
        # Fill other columns
        df_combined['ioc_value'] = df_combined['ioc_value'].fillna('Unknown')
        df_combined['ioc_type'] = df_combined['ioc_type'].fillna('Unknown')
        df_combined['threat_tag'] = df_combined['threat_tag'].fillna('Unknown')
        df_combined['source'] = df_combined['source'].fillna('Unknown')
        
        # Enrichment
        df_combined = enrich_ip(df_combined)
        
        # Sort by date
        df_combined.sort_values(by='date', ascending=False, inplace=True)
        
        # Now we can convert date to string for display/export and fill NaT
        df_combined['date'] = df_combined['date'].dt.strftime('%Y-%m-%d %H:%M:%S').fillna('Unknown')
        
        # Report
        generate_report(df_combined)
        
        # Save
        # Convert date back to string for JSON serialization
        df_export = df_combined.copy()
        df_export['date'] = df_export['date'].astype(str)
        save_data(df_export)

    console.print("[bold blue]ThreatHarvest Finished.[/bold blue]")

if __name__ == "__main__":
    main()
