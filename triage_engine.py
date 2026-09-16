import os
import json
import logging
from typing import Dict, Any
from groq import AsyncGroq

# Configure basic logging for fallback visibility
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def analyze_email(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes email context and VirusTotal enrichment using Groq LLM.
    Forces a strict JSON output schema.
    """
    api_key = os.getenv("GROQ_API_KEY")
    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    
    if not api_key:
        logger.error("GROQ_API_KEY is missing from environment variables.")
        return _get_fallback_response()

    client = AsyncGroq(api_key=api_key)

    # Construct the strict JSON schema instructions
    system_prompt = """
    You are an Expert Tier 3 SOC Analyst AI. Your job is to triage employee-reported phishing emails.
    You will be provided with the email metadata, body preview, and VirusTotal threat intelligence results.
    
    You MUST respond ONLY with a valid JSON object matching this exact schema:
    {
      "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
      "confidence": <int 0-100>,
      "tactics_identified": ["list of strings, e.g., 'Urgency', 'Credential Harvesting'"],
      "executive_summary": "1-2 sentence analyst summary",
      "suggested_remediation": ["list of action steps"]
    }
    Do not include markdown formatting, preamble, or postamble. Output raw JSON only.
    """

    # Inject the enriched data from Phase 1
    user_prompt = f"""
    Please analyze the following reported email:
    
    SENDER: {email_data.get('sender', 'Unknown')}
    SUBJECT: {email_data.get('subject', 'No Subject')}
    
    BODY PREVIEW:
    {email_data.get('body_preview', 'No Body Content')}
    
    VIRUSTOTAL ENRICHMENT RESULTS:
    {json.dumps(email_data.get('vt_results', {}), indent=2)}
    """

    try:
        # Async call to Groq with strict JSON mode enabled
        response = await client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model=model,
            response_format={"type": "json_object"},
            temperature=0.1, # Low temperature for deterministic, analytical output
            max_tokens=1024
        )
        
        raw_json = response.choices[0].message.content
        return json.loads(raw_json)

    except Exception as e:
        # Graceful Fallback: If the API times out, errors, or returns bad JSON, 
        # we fail open (mark as suspicious for human review) rather than crashing the pipeline.
        logger.error(f"Groq API Error or JSON parsing failure: {e}")
        return _get_fallback_response()

def _get_fallback_response() -> Dict[str, Any]:
    """Safe fallback dictionary if the LLM fails."""
    return {
        "verdict": "SUSPICIOUS",
        "confidence": 0,
        "tactics_identified": ["LLM Analysis Failed"],
        "executive_summary": "Automated AI analysis failed or timed out. Manual human review is required.",
        "suggested_remediation": ["Review email manually", "Check Groq API status"]
    }
