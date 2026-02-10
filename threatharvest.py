
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
import matplotlib.pyplot as plt
import matplotlib

# Suppress matplotlib font warnings
matplotlib.rc('font', family='DejaVu Sans')

# Configuration
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
KNOWLEDGE_BASE_FILE = "threat_knowledge_base.json"
GROQ_MODEL = "llama-3.3-70b-versatile"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Directory Structure
DATA_DIR = "data"
OUTPUT_DIR = os.path.join("output", str(datetime.date.today()))  # output/YYYY-MM-DD/

# Architecture terms to filter from malware family extraction
ARCHITECTURE_TERMS = {
    'elf', '32-bit', '64-bit', 'arm', 'mips', 'intel', 'sh', 'powerpc',
    'x86', 'x64', 'amd64', 'i386', 'i686', 'armv7', 'aarch64'
}

# Setup Logging
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
console = Console()

def initialize_directories():
    """Creates required directory structure if it doesn't exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.info(f"Directories initialized: {DATA_DIR}, {OUTPUT_DIR}")

def fetch_urlhaus():
    """Fetches and parses URLhaus CSV."""
    logging.info("Fetching URLhaus data...")
    try:
        df = pd.read_csv(URLHAUS_CSV_URL, skiprows=8, header=0, skipinitialspace=True)
        
        if df.empty:
            logging.warning("URLhaus data is empty.")
            return pd.DataFrame()

        df['source'] = 'URLhaus'
        df['ioc_type'] = 'url'
        
        df.rename(columns={
            'dateadded': 'date',
            'url': 'ioc_value', 
            'tags': 'threat_tag'
        }, inplace=True)
        
        required_cols = ['date', 'ioc_value', 'ioc_type', 'threat_tag', 'source']
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
        df = pd.read_csv(FEODO_BLOCKLIST_URL, skiprows=8, skipinitialspace=True)
        
        if df.empty:
            logging.warning("Feodo Tracker data is empty.")
            return pd.DataFrame()

        df['source'] = 'FeodoTracker'
        df['ioc_type'] = 'ip:port'
        
        df['ioc_value'] = df['dst_ip'] + ':' + df['dst_port'].astype(str)
        df.rename(columns={'first_seen_utc': 'date', 'malware': 'threat_tag'}, inplace=True)
        
        required_cols = ['date', 'ioc_value', 'ioc_type', 'threat_tag', 'source']
        for col in required_cols:
            if col not in df.columns:
                df[col] = None
        
        return df[required_cols]

    except Exception as e:
        logging.error(f"Error fetching Feodo Tracker: {e}")
        return pd.DataFrame()

def extract_malware_family(raw_tag):
    """
    Extracts malware family name from raw threat tag.
    Removes architecture-specific terms and returns the family name.
    """
    if pd.isna(raw_tag) or raw_tag == 'Unknown':
        return 'Unknown'
    
    # Split by comma first (primary delimiter)
    parts = [p.strip() for p in raw_tag.split(',')]
    
    # Filter out architecture terms and look for capitalized family names
    family_candidates = []
    for part in parts:
        # Check if entire part is an architecture term
        if part.lower() in ARCHITECTURE_TERMS:
            continue
        
        # Check if part contains hyphens (like "32-bit")
        if '-' in part:
            # Split by hyphen and check each sub-part
            sub_parts = part.split('-')
            # If any sub-part is architecture term, skip the whole thing
            if any(sp.lower() in ARCHITECTURE_TERMS for sp in sub_parts):
                continue
        
        # Valid candidate if it's longer than 2 chars
        if len(part) > 2:
            family_candidates.append(part)
    
    # Prioritize capitalized names (likely family names like "Mozi", "Mirai")
    for candidate in family_candidates:
        if candidate[0].isupper():
            return candidate
    
    # Otherwise return first valid candidate
    if family_candidates:
        return family_candidates[0].capitalize()
    
    return 'Unknown'

def standardize_data(df):
    """
    Standardizes data schema with snake_case keys and ISO timestamps.
    Adds malware_family, collected_at fields.
    """
    if df.empty:
        return df
    
    # Parse dates
    df['date'] = pd.to_datetime(df['date'], errors='coerce')
    
    # Add ISO 8601 timestamp
    df['collected_at'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Fill NaN values
    df['ioc_value'] = df['ioc_value'].fillna('Unknown')
    df['ioc_type'] = df['ioc_type'].fillna('Unknown')
    df['threat_tag'] = df['threat_tag'].fillna('Unknown')
    df['source'] = df['source'].fillna('Unknown')
    
    # Extract malware family
    df['malware_family'] = df['threat_tag'].apply(extract_malware_family)
    
    # Sort by date
    df.sort_values(by='date', ascending=False, inplace=True)
    
    # Convert date to string for JSON serialization
    df['date'] = df['date'].dt.strftime('%Y-%m-%d %H:%M:%S').fillna('Unknown')
    
    return df

def load_previous_data():
    """Loads the most recent previous threat feed (JSON) for trend analysis."""
    files = glob.glob(os.path.join(DATA_DIR, "threat_feed_*.json"))
    if not files:
        return pd.DataFrame()
    
    files.sort(reverse=True)
    
    today_filename = os.path.join(DATA_DIR, f"threat_feed_{datetime.date.today()}.json")
    
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

def get_new_entrants(df_today, df_prev):
    """Identifies threat tags present today but not in the previous report."""
    if df_today.empty or 'threat_tag' not in df_today.columns:
        return []
    
    today_tags = set(df_today['threat_tag'].unique())
    
    if df_prev.empty or 'threat_tag' not in df_prev.columns:
        return []
        
    prev_tags = set(df_prev['threat_tag'].unique())
    
    new_entrants = list(today_tags - prev_tags)
    return new_entrants

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
        # Clean potential markdown code blocks
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

def generate_pie_chart(df):
    """Generates pie chart for Top 5 malware families distribution."""
    if df.empty or 'malware_family' not in df.columns:
        return
    
    try:
        plt.style.use('dark_background')
        fig, ax = plt.subplots(figsize=(10, 8))
        
        # Get top 5 families
        family_counts = df['malware_family'].value_counts().head(5)
        
        colors = ['#00ff41', '#ff4444', '#ffaa00', '#00aaff', '#ff00ff']
        
        wedges, texts, autotexts = ax.pie(
            family_counts.values, 
            labels=family_counts.index,
            autopct='%1.1f%%',
            colors=colors,
            startangle=90,
            textprops={'color': 'white', 'fontsize': 12}
        )
        
        for autotext in autotexts:
            autotext.set_color('black')
            autotext.set_fontweight('bold')
        
        ax.set_title('Top 5 Malware Families Distribution', fontsize=16, color='white', pad=20)
        
        filename = os.path.join(OUTPUT_DIR, "distrib_famille.png")
        plt.tight_layout()
        plt.savefig(filename, dpi=100, facecolor='black')
        plt.close()
        
        logging.info(f"Pie chart saved to {filename}")
    except Exception as e:
        logging.error(f"Error generating pie chart: {e}")

def generate_histogram(df_today, df_prev):
    """Generates histogram comparing today's vs yesterday's threat volume."""
    try:
        plt.style.use('dark_background')
        fig, ax = plt.subplots(figsize=(10, 6))
        
        today_count = len(df_today) if not df_today.empty else 0
        yesterday_count = len(df_prev) if not df_prev.empty else 0
        
        labels = ['Yesterday', 'Today']
        counts = [yesterday_count, today_count]
        colors = ['#ffaa00', '#00ff41']
        
        bars = ax.bar(labels, counts, color=colors, edgecolor='white', linewidth=2)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height):,}',
                   ha='center', va='bottom', color='white', fontsize=14, fontweight='bold')
        
        ax.set_ylabel('Total Threats', fontsize=12, color='white')
        ax.set_title('Threat Volume Evolution', fontsize=16, color='white', pad=20)
        ax.tick_params(colors='white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        filename = os.path.join(OUTPUT_DIR, "evolution_volumetrie.png")
        plt.tight_layout()
        plt.savefig(filename, dpi=100, facecolor='black')
        plt.close()
        
        logging.info(f"Histogram saved to {filename}")
    except Exception as e:
        logging.error(f"Error generating histogram: {e}")

def generate_html_report(df, new_entrants, ai_briefing_data):
    """Generates HTML report with dark mode styling."""
    today = datetime.date.today()
    filename = os.path.join(OUTPUT_DIR, f"report_{today}.html")
    
    try:
        # Get top 10 for table
        top_10 = df['threat_tag'].value_counts().head(10)
        
        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatHarvest Report - {today}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            background: #0a0a0a;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: #00ff41;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
            text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
        }}
        .date {{
            text-align: center;
            color: #888;
            margin-bottom: 40px;
            font-size: 1.2em;
        }}
        .section {{
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        h2 {{
            color: #00ff41;
            margin-bottom: 20px;
            border-bottom: 2px solid #00ff41;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th {{
            background: #00ff41;
            color: #000;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #333;
        }}
        tr:hover {{
            background: #252525;
        }}
        .chart-container {{
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
        }}
        .chart {{
            flex: 1;
            min-width: 400px;
            text-align: center;
        }}
        .chart img {{
            max-width: 100%;
            border-radius: 8px;
            border: 1px solid #333;
        }}
        .ai-summary {{
            background: #1a2a1a;
            border-left: 4px solid #00ff41;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .new-threats {{
            background: #2a1a1a;
            border-left: 4px solid #ff4444;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .new-threats h3 {{
            color: #ff4444;
            margin-bottom: 15px;
        }}
        .threat-list {{
            list-style: none;
            padding-left: 0;
        }}
        .threat-list li {{
            padding: 8px 0;
            border-bottom: 1px solid #333;
        }}
        .threat-list li:before {{
            content: "▸ ";
            color: #ff4444;
            font-weight: bold;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: #252525;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #333;
        }}
        .stat-number {{
            font-size: 2.5em;
            color: #00ff41;
            font-weight: bold;
        }}
        .stat-label {{
            color: #888;
            margin-top: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ ThreatHarvest Intelligence Report</h1>
        <div class="date">{today.strftime('%B %d, %Y')}</div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{len(df):,}</div>
                <div class="stat-label">Total IOCs Collected</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(df['malware_family'].unique())}</div>
                <div class="stat-label">Unique Malware Families</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(new_entrants)}</div>
                <div class="stat-label">New Threats Detected</div>
            </div>
        </div>
"""
        
        # AI Strategic Summary
        if ai_briefing_data:
            html += """
        <div class="section">
            <h2>🧠 AI Strategic Briefing</h2>
            <div class="ai-summary">
                <table>
                    <tr>
                        <th>Threat Tag</th>
                        <th>Family</th>
                        <th>Description</th>
                        <th>Risk</th>
                        <th>Source</th>
                    </tr>
"""
            for item in ai_briefing_data:
                risk_color = '#ff4444' if item['risk'] in ['Critical', 'High'] else '#ffaa00' if item['risk'] == 'Medium' else '#00ff41'
                html += f"""
                    <tr>
                        <td>{item['tag']}</td>
                        <td>{item['family']}</td>
                        <td>{item['description']}</td>
                        <td style="color: {risk_color}; font-weight: bold;">{item['risk']}</td>
                        <td>{item['source']}</td>
                    </tr>
"""
            html += """
                </table>
            </div>
        </div>
"""
        
        # New Threats
        if new_entrants:
            html += """
        <div class="section">
            <div class="new-threats">
                <h3>⚠️ New Threats Detected</h3>
                <ul class="threat-list">
"""
            for threat in new_entrants[:20]:  # Limit to 20 for readability
                html += f"                    <li>{threat}</li>\n"
            
            if len(new_entrants) > 20:
                html += f"                    <li><em>... and {len(new_entrants) - 20} more</em></li>\n"
            
            html += """
                </ul>
            </div>
        </div>
"""
        
        # Visualizations
        html += """
        <div class="section">
            <h2>📊 Threat Analysis Visualizations</h2>
            <div class="chart-container">
                <div class="chart">
                    <h3>Malware Family Distribution</h3>
                    <img src="distrib_famille.png" alt="Malware Family Distribution">
                </div>
                <div class="chart">
                    <h3>Volume Evolution</h3>
                    <img src="evolution_volumetrie.png" alt="Volume Evolution">
                </div>
            </div>
        </div>
"""
        
        # Top 10 Table
        html += """
        <div class="section">
            <h2>🎯 Top 10 Threats</h2>
            <table>
                <tr>
                    <th>Rank</th>
                    <th>Threat Tag</th>
                    <th>Count</th>
                </tr>
"""
        for idx, (tag, count) in enumerate(top_10.items(), 1):
            html += f"""
                <tr>
                    <td>{idx}</td>
                    <td>{tag}</td>
                    <td>{count:,}</td>
                </tr>
"""
        
        html += """
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logging.info(f"HTML report saved to {filename}")
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")

def generate_console_report(df, df_prev, new_entrants):
    """Generates console report using Rich with Trend Analysis."""
    if df.empty:
        console.print("[bold red]No data to report.[/bold red]")
        return
    
    prev_counts = {}
    if not df_prev.empty and 'threat_tag' in df_prev.columns:
        prev_counts = df_prev['threat_tag'].value_counts().to_dict()
    
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
            trend_str = "[bold orange1]New *[/bold orange1]"
             
        table.add_row(str(idx), str(tag), str(count), trend_str)
    
    console.print(table)
    
    # New Detections Section
    if new_entrants:
        console.print()
        console.print(Panel(
            "\n".join([f"[red]> {tag}[/red]" for tag in new_entrants[:10]]) + 
            (f"\n\n[dim]... and {len(new_entrants)-10} more[/dim]" if len(new_entrants) > 10 else ""),
            title="[bold red][!] NOUVELLES MENACES DETECTEES[/bold red]",
            border_style="red",
            expand=False
        ))
    else:
        console.print("\n[bold green]Aucune nouvelle menace détectée par rapport au précédent rapport.[/bold green]")
    
    console.print(f"\n[bold]Total IOCs Collected:[/bold] {len(df):,}")
    console.print(f"[bold]Unique Malware Families:[/bold] {len(df['malware_family'].unique())}")

def generate_ai_briefing(df):
    """Generates AI-powered Strategic Briefing for top threats."""
    if df.empty:
        return []
    
    console.print()
    console.print(Panel("[bold yellow][AI] Strategic Briefing[/bold yellow]", expand=False))
    
    top_tags = df['threat_tag'].value_counts().head(5).index.tolist()
    
    kb = load_knowledge_base()
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Threat Tag", style="dim", width=30)
    table.add_column("Family", style="cyan")
    table.add_column("Description")
    table.add_column("Risk", justify="center")
    table.add_column("Source", style="italic")
    
    briefing_data = []
    
    with console.status("[bold green]Analyzing threats with AI...[/bold green]"):
        for tag in top_tags:
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
            
            briefing_data.append({
                'tag': tag,
                'family': analysis.get('family', 'N/A'),
                'description': analysis.get('description', 'N/A'),
                'risk': risk,
                'source': analysis.get('source', 'Unknown')
            })
    
    console.print(table)
    return briefing_data

def save_data(df):
    """Saves consolidated data to JSON with date-based filename."""
    try:
        result = df.to_dict(orient='records')
        
        filename = os.path.join(DATA_DIR, f"threat_feed_{datetime.date.today()}.json")
        
        with open(filename, 'w') as f:
            json.dump(result, f, indent=4)
        logging.info(f"Data saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving data: {e}")

def main():
    console.print("[bold blue]ThreatHarvest Started...[/bold blue]")
    
    # Initialize directory structure
    initialize_directories()
    
    # Fetch data
    df_urlhaus = fetch_urlhaus()
    df_feodo = fetch_feodo()
    
    frames = [df_urlhaus, df_feodo]
    df_combined = pd.concat(frames, ignore_index=True)
    
    if df_combined.empty:
        logging.warning("No data collected from any source.")
        return
    
    # Standardize data
    df_combined = standardize_data(df_combined)
    
    # Load previous data for comparison
    df_prev = load_previous_data()
    
    # Get new entrants
    new_entrants = get_new_entrants(df_combined, df_prev)
    
    # Console Report
    generate_console_report(df_combined, df_prev, new_entrants)
    
    # AI Briefing
    ai_briefing_data = generate_ai_briefing(df_combined)
    
    # Generate Visualizations
    generate_pie_chart(df_combined)
    generate_histogram(df_combined, df_prev)
    
    # Generate HTML Report
    generate_html_report(df_combined, new_entrants, ai_briefing_data)
    
    # Save data
    save_data(df_combined)
    
    console.print("[bold blue]ThreatHarvest Finished.[/bold blue]")
    console.print(f"[bold green]Report available at: {os.path.join(OUTPUT_DIR, f'report_{datetime.date.today()}.html')}[/bold green]")

if __name__ == "__main__":
    main()
