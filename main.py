import os
import asyncio
import aiohttp
import discord
from discord.ext import tasks, commands
from dotenv import load_dotenv

# Import our custom modules
from database import (
    init_db,
    insert_submission,
    get_all_pending_submissions,
    update_submission_analysis,
    get_analyzed_submissions,
    mark_submission_posted
)
from imap_engine import IMAPEngine
from vt_client import VTClient
from triage_engine import analyze_email

# Load environment variables
load_dotenv()
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
CHANNEL_ID = int(os.getenv("DISCORD_ALERT_CHANNEL_ID", 0))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", 30))

# Configure Bot Intents
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)


def build_triage_embed(submission: dict) -> discord.Embed:
    """Constructs a visually distinct Discord Embed based on the LLM's verdict."""
    analysis = submission.get('analysis', {})
    verdict = analysis.get('verdict', 'UNKNOWN').upper()
    
    if verdict == "MALICIOUS":
        color = discord.Color.red()
    elif verdict == "SUSPICIOUS":
        color = discord.Color.orange()
    elif verdict == "SAFE":
        color = discord.Color.green()
    else:
        color = discord.Color.default()

    embed = discord.Embed(
        title=f"🎣 Phishing Triage: {submission.get('subject', 'No Subject')}",
        description=f"**Sender:** `{submission.get('sender', 'Unknown')}`",
        color=color
    )
    
    embed.add_field(name="Verdict", value=f"**{verdict}**", inline=True)
    embed.add_field(name="AI Confidence", value=f"{analysis.get('confidence', 0)}%", inline=True)
    
    tactics = analysis.get('tactics_identified', [])
    tactics_str = ", ".join(tactics) if tactics else "None identified"
    embed.add_field(name="Tactics Identified", value=tactics_str, inline=False)
    
    embed.add_field(name="Executive Summary", value=analysis.get('executive_summary', 'N/A'), inline=False)
    
    remediation = analysis.get('suggested_remediation', [])
    remediation_str = "\n".join([f"- {r}" for r in remediation]) if remediation else "N/A"
    embed.add_field(name="Suggested Remediation", value=remediation_str, inline=False)
    
    embed.set_footer(text=f"WIWP Triage Engine | Submission ID: {submission['id']}")
    return embed


@tasks.loop(seconds=POLL_INTERVAL)
async def soc_pipeline_loop():
    """
    The main daemon loop. Executes Ingestion, Triage, and Alerting sequentially.
    Sequential execution prevents SQLite database locking issues.
    """
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        print(f"[!] Warning: Could not find Discord channel with ID {CHANNEL_ID}")
        return

    # ==========================================
    # STEP 1: INGESTION & ENRICHMENT (PHASE 1)
    # ==========================================
    imap_engine = IMAPEngine()
    emails = await imap_engine.fetch_unseen()
    
    if emails:
        print(f"[*] Ingestion: Found {len(emails)} new email(s). Enriching...")
        vt_client = VTClient()
        async with aiohttp.ClientSession() as session:
            for mail in emails:
                vt_results = {"urls": {}, "hashes": {}}
                
                # Enrich URLs
                for raw_url, defanged in zip(mail['raw_urls'], mail['defanged_urls']):
                    res = await vt_client.check_url(session, raw_url)
                    vt_results["urls"][defanged] = res
                
                # Enrich Hashes
                for file_hash in mail['attachment_hashes']:
                    res = await vt_client.check_hash(session, file_hash)
                    vt_results["hashes"][file_hash] = res
                
                mail["vt_results"] = vt_results
                insert_submission(mail)

    # ==========================================
    # STEP 2: AI TRIAGE (PHASE 2)
    # ==========================================
    pending_submissions = get_all_pending_submissions()
    if pending_submissions:
        print(f"[*] Triage: Analyzing {len(pending_submissions)} pending submission(s)...")
        for sub in pending_submissions:
            analysis_result = await analyze_email(sub)
            update_submission_analysis(sub['id'], analysis_result)

    # ==========================================
    # STEP 3: DISCORD ALERTING (PHASE 3)
    # ==========================================
    analyzed_submissions = get_analyzed_submissions()
    if analyzed_submissions:
        print(f"[*] Alerting: Posting {len(analyzed_submissions)} analyzed submission(s) to Discord...")
        for sub in analyzed_submissions:
            embed = build_triage_embed(sub)
            
            # Send the embed without the interactive view
            await channel.send(embed=embed)
            
            # Mark as posted so we don't spam the channel on the next loop
            mark_submission_posted(sub['id'])


@bot.event
async def on_ready():
    print(f"[+] Logged in as {bot.user} (ID: {bot.user.id})")
    print("[*] Initializing database...")
    init_db()
    print(f"[*] Starting SOC Pipeline Loop (Interval: {POLL_INTERVAL}s)...")
    soc_pipeline_loop.start()


if __name__ == "__main__":
    if not TOKEN or not CHANNEL_ID:
        print("[!] ERROR: DISCORD_BOT_TOKEN or DISCORD_ALERT_CHANNEL_ID is missing from .env")
    else:
        # Run the unified daemon
        bot.run(TOKEN)
