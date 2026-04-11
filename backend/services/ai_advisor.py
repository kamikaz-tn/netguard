"""
netguard/backend/services/ai_advisor.py
─────────────────────────────────────────
Google Gemini-powered security advisor using the new google-genai package.
Builds a context-aware system prompt from the latest scan results
so the AI can give specific advice about the user's actual network.
"""
 
import asyncio
import os
from google import genai
from google.genai import types
from typing import List, Optional
from models.schemas import ChatMessage
from core.config import settings
 
 
# ── Gemini client (initialized once) ──────────────────────────────────────────
_client = None
 
 
def get_client():
    global _client
    if _client is None:
        api_key = settings.gemini_api_key or os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not set")
        _client = genai.Client(api_key=api_key)
    return _client
 
# ── System prompt builder ──────────────────────────────────────────────────────
def build_system_prompt(scan_context: Optional[dict] = None) -> str:
    base_prompt = """You are NetGuard AI, an expert cybersecurity advisor embedded inside a network monitoring dashboard called NetGuard.
 
Your role:
- Explain scan results, open ports, and network threats in plain, accessible language
- Give actionable, step-by-step remediation advice
- Educate users who are not security experts – avoid overwhelming jargon
- Be concise but thorough – the user is reading in a dashboard, not a book
- When you mention a port, always explain what it does in simple terms
- Always end responses with a clear "What to do next" when relevant
 
Tone: Friendly but serious. Like a knowledgeable friend who happens to be a security professional.
Format: Use short paragraphs. Use numbered steps for remediation. Keep responses under 300 words unless the user asks for detail."""
 
    if not scan_context:
        return base_prompt
 
    context_block = "\n\n--- CURRENT NETWORK SCAN DATA ---\n"
    context_block += f"Network: {scan_context.get('network_range', 'Unknown')}\n"
    context_block += f"Devices found: {scan_context.get('hosts_up', 0)}\n"
    context_block += f"Open ports: {scan_context.get('total_ports', 0)}\n"
    context_block += f"Threats detected: {scan_context.get('threats_found', 0)}\n"
    context_block += f"Risk score: {scan_context.get('risk_score', 0)}/100\n"
 
    findings = scan_context.get("findings", [])
    if findings:
        context_block += "\nKey findings:\n"
        for f in findings[:5]:
            context_block += (
                f"  [{f.get('severity','?').upper()}] "
                f"{f.get('host_ip','?')} – port {f.get('port','?')} "
                f"({f.get('service','?')}): {f.get('description','')[:80]}...\n"
            )
 
    context_block += "\nUse this data to give specific, targeted advice when relevant."
    context_block += "\n--- END SCAN DATA ---"
 
    return base_prompt + context_block
 
 
# ── Chat completion ────────────────────────────────────────────────────────────
async def get_ai_response(
    messages: List[ChatMessage],
    scan_context: Optional[dict] = None,
) -> str:
    system_prompt = build_system_prompt(scan_context)
 
    # Convert messages to Gemini format
    history = []
    for msg in messages[:-1]:  # all except the last message
        role = "user" if msg.role == "user" else "model"
        history.append(types.Content(role=role, parts=[types.Part(text=msg.content)]))
 
    last_message = messages[-1].content
 
    def _call():
        client = get_client()
        chat = client.chats.create(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=8192,
                temperature=0.7,
            ),
            history=history,
        )
        response = chat.send_message(last_message)
        return response.text
 
    return await asyncio.get_event_loop().run_in_executor(None, _call)
