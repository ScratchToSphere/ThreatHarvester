
import pandas as pd
import requests
import logging
import datetime
import os
import json
import glob
from groq import Groq
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Configuration
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
KNOWLEDGE_BASE_FILE = "threat_knowledge_base.json"
GROQ_MODEL = "llama-3.3-70b-versatile"
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

def load_previous_data():
    """Loads the most recent previous threat feed (JSON) for trend analysis."""
    # Find all threat_feed_*.json files
    files = glob.glob("threat_feed_*.json")
    if not files:
        return pd.DataFrame()
    
    # Sort by name (which contains date) to get the latest
    files.sort(reverse=True)
    
    # Get today's filename to avoid comparing against itself if run multiple times same day
    today_filename = f"threat_feed_{datetime.date.today()}.json"
    
    target_file = None
    for f in files:
        if f != today_filename:
            target_file = f
            break
            
    if not target_file:
        return pd.DataFrame()
        
    logging.info(f"Loading previous data from {target_file} for trend analysis.")
    try:
        with open(target_file, 'r') as f:
            data = json.load(f)
        return pd.DataFrame(data)
    except Exception as e:
        logging.error(f"Error loading previous data: {e}")
        return pd.DataFrame()

def generate_report(df):
    """Generates console report using Rich with Trend Analysis."""
    if df.empty:
        console.print("[bold red]No data to report.[/bold red]")
        return

    # Load previous data for trends
    df_prev = load_previous_data()
    prev_counts = {}
    if not df_prev.empty and 'threat_tag' in df_prev.columns:
        prev_counts = df_prev['threat_tag'].value_counts().to_dict()

    # Top 10 Malwares (Threat Tags)
    top_threats = df['threat_tag'].value_counts().head(10)

    table = Table(title="Top 10 Malwares of the Day")
    table.add_column("Rank", justify="right", style="cyan", no_wrap=True)
    table.add_column("Malware / Tag", style="magenta")
    table.add_column("Count", justify="right", style="green")
    table.add_column("Trend", justify="center")

    for idx, (tag, count) in enumerate(top_threats.items(), 1):
        trend_str = "[dim]=[/dim]"
        if tag in prev_counts:
            delta = count - prev_counts[tag]
            if delta > 0:
                trend_str = f"[bold red]+{delta} ^[/bold red]"
            elif delta < 0:
                trend_str = f"[bold green]{delta} v[/bold green]"
        elif not df_prev.empty:
             # Only show "New" if we actually have previous data to compare against
             trend_str = "[bold orange1]New *[/bold orange1]"
             
        table.add_row(str(idx), str(tag), str(count), trend_str)

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

def load_knowledge_base():
    """Loads the local threat knowledge base JSON."""
    if os.path.exists(KNOWLEDGE_BASE_FILE):
        try:
            with open(KNOWLEDGE_BASE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading knowledge base: {e}")
            return {}
    return {}

def save_knowledge_base(kb):
    """Saves the threat knowledge base to JSON."""
    try:
        with open(KNOWLEDGE_BASE_FILE, 'w') as f:
            json.dump(kb, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving knowledge base: {e}")

def analyze_threat_with_ai(tag, kb):
    """
    Analyzes a threat tag using AI (Groq) or Knowledge Base.
    Returns a dict with keys: family, description, risk, source.
    """
    # 1. Check Cache
    if tag in kb:
        result = kb[tag]
        result['source'] = 'Cache'
        return result

    # 2. Check API Key
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {"family": "Unknown", "description": "AI features disabled (No API Key).", "risk": "Unknown", "source": "Skipped"}
    
    # 3. Ask Groq
    try:
        client = Groq(api_key=api_key)
        prompt = f"""
        Analyze this malware threat tag: "{tag}".
        Provide a JSON response with exactly these fields:
        - "family": The malware family name (e.g., Mirai, Cobalt Strike).
        - "description": A very short description (max 15 words).
        - "risk": Risk level (Low, Medium, High, Critical).
        
        Return ONLY valid JSON. No markdown formatting.
        """
        
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Output only JSON."},
                {"role": "user", "content": prompt}
            ],
            model=GROQ_MODEL,
            temperature=0.1,
        )
        
        response_content = chat_completion.choices[0].message.content.strip()
        # Clean potential markdown code blocks if Llama includes them
        if response_content.startswith("```"):
            response_content = response_content.strip("`").replace("json", "").strip()
            
        analysis = json.loads(response_content)
        
        # 4. Save to Cache
        kb[tag] = analysis
        save_knowledge_base(kb)
        
        analysis['source'] = 'AI Live'
        return analysis

    except Exception as e:
        logging.error(f"AI Analysis failed for {tag}: {e}")
        return {"family": "Unknown", "description": "Analysis failed.", "risk": "Unknown", "source": "Error"}

def generate_ai_briefing(df):
    """Generates an AI-powered Strategic Briefing for top threats."""
    if df.empty:
        return

    console.print()
    console.print(Panel("[bold yellow][AI] Strategic Briefing[/bold yellow]", expand=False))
    
    # Get top 5 unique tags for briefing to save time/tokens
    top_tags = df['threat_tag'].value_counts().head(5).index.tolist()
    
    kb = load_knowledge_base()
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Threat Tag", style="dim", width=30)
    table.add_column("Family", style="cyan")
    table.add_column("Description")
    table.add_column("Risk", justify="center")
    table.add_column("Source", style="italic")

    with console.status("[bold green]Analyzing threats with AI...[/bold green]"):
        for tag in top_tags:
            # Skip "Unknown" tags if possible or handle them gracefully
            if tag.lower() == 'unknown':
                continue
                
            analysis = analyze_threat_with_ai(tag, kb)
            
            risk_style = "white"
            risk = analysis.get('risk', 'Unknown')
            if risk == 'Critical': risk_style = "bold red"
            elif risk == 'High': risk_style = "red"
            elif risk == 'Medium': risk_style = "yellow"
            
            source_style = "blue" if analysis.get('source') == 'AI Live' else "green"
            
            table.add_row(
                tag,
                analysis.get('family', 'N/A'),
                analysis.get('description', 'N/A'),
                f"[{risk_style}]{risk}[/{risk_style}]",
                f"[{source_style}]{analysis.get('source', 'Unknown')}[/{source_style}]"
            )

    console.print(table)


def save_data(df):
    """Saves consolidated data to JSON with date-based filename."""
    try:
        # Convert to list of dicts for JSON export, handling dates strings
        result = df.to_dict(orient='records')
        
        filename = f"threat_feed_{datetime.date.today()}.json"
        
        with open(filename, 'w') as f:
            json.dump(result, f, indent=4)
        logging.info(f"Data saved to {filename}")
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
        
        # AI Briefing
        generate_ai_briefing(df_combined)
        
        # Save
        # Convert date back to string for JSON serialization
        df_export = df_combined.copy()
        df_export['date'] = df_export['date'].astype(str)
        save_data(df_export)

    console.print("[bold blue]ThreatHarvest Finished.[/bold blue]")

if __name__ == "__main__":
    main()
