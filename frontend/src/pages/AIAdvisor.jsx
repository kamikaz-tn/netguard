import { useState, useRef, useEffect } from 'react'
import { chat as chatApi, scan } from '../services/api.js'

const QUICK_ASKS = [
  'What does port 4444 being open mean?',
  'How do I kick a device from my network?',
  'What is a backdoor and how do I detect one?',
  'How do I create a strong password?',
  'Is Telnet port 23 dangerous?',
  'What is ARP scanning?',
]

function Message({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div style={{
      display: 'flex',
      justifyContent: isUser ? 'flex-end' : 'flex-start',
      marginBottom: 12,
      animation: 'fadeIn 0.2s ease',
    }}>
      <div style={{
        maxWidth: '80%',
        padding: '10px 14px',
        borderRadius: 'var(--radius)',
        fontSize: 13,
        lineHeight: 1.65,
        background: isUser ? 'var(--green-dim)' : 'var(--surface2)',
        border: `1px solid ${isUser ? 'rgba(0,229,160,0.25)' : 'var(--border)'}`,
        color: isUser ? 'var(--green)' : 'var(--text)',
        fontFamily: isUser ? 'var(--font-mono)' : 'var(--font)',
      }}>
        {!isUser && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, marginBottom: 6 }}>NETGUARD AI</div>
        )}
        <div style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</div>
      </div>
    </div>
  )
}

function TypingIndicator() {
  return (
    <div style={{ display: 'flex', gap: 5, padding: '8px 0 4px 4px', alignItems: 'center' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', letterSpacing: 2, marginRight: 4 }}>NETGUARD AI</div>
      {[0, 1, 2].map(i => (
        <div key={i} style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--green)', animation: `pulse 1.2s infinite ${i * 0.2}s` }} />
      ))}
    </div>
  )
}

export default function AIAdvisor() {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: "Hey! I'm NetGuard AI, your network security advisor. I can explain scan results, help you understand threats, walk you through fixes, or answer any cybersecurity question. What do you want to know?" }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanContext, setScanContext] = useState(null)
  const bottomRef = useRef()

  useEffect(() => {
    loadScanContext()
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  async function loadScanContext() {
    try {
      const history = await scan.history(1)
      if (history?.length > 0) setScanContext(history[0])
    } catch {}
  }

  async function sendMessage(text) {
    const userMsg = text || input.trim()
    if (!userMsg) return
    setInput('')

    const updatedMessages = [...messages, { role: 'user', content: userMsg }]
    setMessages(updatedMessages)
    setLoading(true)

    try {
      const res = await chatApi.send(
        updatedMessages.filter(m => m.role !== 'system'),
      )
      setMessages(prev => [...prev, { role: 'assistant', content: res.reply }])
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: `⚠ Error: ${err.message}. Make sure your Gemini API key is set in backend/.env` }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="animate-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 48px)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <h1 style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text)', letterSpacing: 2 }}>AI SECURITY ADVISOR</h1>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
            {scanContext ? `Context: scan from ${new Date(scanContext.created_at).toLocaleDateString()} — ${scanContext.threats_found} threats` : 'No scan context loaded'}
          </div>
        </div>
        <button className="btn-ghost" onClick={() => setMessages([messages[0]])}>CLEAR CHAT</button>
      </div>

      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 16 }}>

        {/* Messages */}
        <div style={{ flex: 1, overflowY: 'auto', paddingRight: 4 }}>
          {messages.map((msg, i) => <Message key={i} msg={msg} />)}
          {loading && <TypingIndicator />}
          <div ref={bottomRef} />
        </div>

        {/* Quick asks */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', padding: '12px 0 10px', borderTop: '1px solid var(--border)' }}>
          {QUICK_ASKS.map(q => (
            <button key={q} onClick={() => sendMessage(q)} disabled={loading}
              style={{ background: 'transparent', border: '1px solid var(--border2)', color: 'var(--muted)', fontSize: 9, padding: '4px 10px', borderRadius: 'var(--radius)', cursor: 'pointer', fontFamily: 'var(--font-mono)', letterSpacing: 0.5, transition: 'all 0.15s' }}
              onMouseEnter={e => { e.target.style.color = 'var(--text)'; e.target.style.borderColor = 'var(--text)' }}
              onMouseLeave={e => { e.target.style.color = 'var(--muted)'; e.target.style.borderColor = 'var(--border2)' }}>
              {q}
            </button>
          ))}
        </div>

        {/* Input */}
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
            placeholder="Ask anything about network security..."
            disabled={loading}
          />
          <button className="btn-primary" onClick={() => sendMessage()} disabled={loading || !input.trim()} style={{ flexShrink: 0, padding: '10px 20px' }}>
            SEND
          </button>
        </div>
      </div>
    </div>
  )
}
