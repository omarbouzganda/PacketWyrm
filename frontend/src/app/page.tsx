'use client';

import { useState, useEffect, useRef } from 'react';

// ============================================================================
// CONFIG
// ============================================================================

const PROTOCOLS = [
  { name: 'ALL', color: '#58a6ff', icon: '📡' },
  { name: 'HTTP', color: '#3fb950', icon: '🌐' },
  { name: 'HTTPS', color: '#58a6ff', icon: '🔒' },
  { name: 'DNS', color: '#d29922', icon: '🔍' },
  { name: 'TCP', color: '#39c5cf', icon: '📡' },
  { name: 'UDP', color: '#a371f7', icon: '📦' },
  { name: 'ICMP', color: '#db6d28', icon: '📶' },
  { name: 'SSH', color: '#f85149', icon: '🔑' },
  { name: 'ARP', color: '#8b949e', icon: '🏠' },
];

const BLACKLIST = ['185.220.101.45', '45.33.32.156', '198.199.119.0'];

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function PacketWyrm() {
  const [packets, setPackets] = useState<any[]>([]);
  const [hosts, setHosts] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [running, setRunning] = useState(false);
  const [connected, setConnected] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Connect to backend
  useEffect(() => {
    const connect = () => {
      try {
        wsRef.current = new WebSocket('ws://localhost:8080/ws');
        
        wsRef.current.onopen = () => {
          setConnected(true);
          console.log('✅ Connected to backend');
        };
        
        wsRef.current.onmessage = (e) => {
          const msg = JSON.parse(e.data);
          if (msg.type === 'packet') {
            setPackets(p => [msg.data, ...p].slice(0, 500));
          } else if (msg.type === 'stats') {
            setStats(msg.data);
          }
        };
        
        wsRef.current.onclose = () => {
          setConnected(false);
          setTimeout(connect, 3000);
        };
      } catch {
        setConnected(false);
      }
    };
    
    connect();
    return () => wsRef.current?.close();
  }, []);

  // Demo mode - generates fake packets when backend not connected
  useEffect(() => {
    if (!connected) {
      const interval = setInterval(() => {
        const protos = ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'SSH', 'ARP'];
        const proto = protos[Math.floor(Math.random() * protos.length)];
        const src = `192.168.1.${Math.floor(Math.random() * 254) + 1}`;
        const dst = ['8.8.8.8', '1.1.1.1', '142.250.80.14', '172.217.14.110'][Math.floor(Math.random() * 4)];
        
        setPackets(p => [{
          id: Date.now() + Math.random(),
          timestamp: new Date().toISOString(),
          src_ip: src,
          dst_ip: dst,
          src_port: Math.floor(Math.random() * 60000) + 1024,
          dst_port: Math.floor(Math.random() * 60000) + 1024,
          protocol: proto,
          size: Math.floor(Math.random() * 1400) + 40,
          plain_english: `${proto} traffic`,
          is_threat: BLACKLIST.includes(src) || BLACKLIST.includes(dst),
          risk_score: BLACKLIST.includes(src) ? 95 : 10,
        }, ...p].slice(0, 500));
      }, 500);
      
      return () => clearInterval(interval);
    }
  }, [connected]);

  // Update hosts
  useEffect(() => {
    const h: any = {};
    packets.forEach(p => {
      if (!h[p.src_ip]) h[p.src_ip] = { ip: p.src_ip, count: 0, bytes: 0 };
      h[p.src_ip].count++;
      h[p.src_ip].bytes += p.size;
    });
    setHosts(Object.values(h).sort((a: any, b: any) => b.count - a.count));
  }, [packets]);

  // Filter
  const filtered = packets.filter(p => {
    if (filter !== 'ALL' && p.protocol !== filter) return false;
    if (search && !`${p.src_ip} ${p.dst_ip} ${p.protocol}`.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  // Export
  const exportCSV = () => {
    const csv = 'Time,Source,Destination,Protocol,Size\n' + 
      filtered.map(p => `${p.timestamp},${p.src_ip},${p.dst_ip},${p.protocol},${p.size}`).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'packets.csv';
    a.click();
  };

  // Styles
  const bg = '#0d1117';
  const surface = '#161b22';
  const border = '#30363d';
  const text = '#f0f6fc';
  const muted = '#8b949e';

  return (
    <div style={{ fontFamily: "'JetBrains Mono', monospace", background: bg, color: text, minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* Header */}
      <header style={{ background: surface, borderBottom: `1px solid ${border}`, padding: '12px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 28 }}>🐉</span>
          <div>
            <div style={{ fontWeight: 800, fontSize: 18, background: 'linear-gradient(135deg, #58a6ff, #a371f7)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>PACKETWYRM</div>
            <div style={{ fontSize: 10, color: muted }}>Network Guardian</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: border, padding: '4px 12px', borderRadius: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: connected ? '#3fb950' : '#f85149' }} />
            <span style={{ fontSize: 11, color: connected ? '#3fb950' : '#f85149' }}>{connected ? 'LIVE' : 'DEMO'}</span>
          </div>
          <span style={{ color: muted, fontSize: 11 }}>{packets.length} pkts</span>
          <button onClick={exportCSV} style={{ padding: '6px 12px', borderRadius: 6, border: `1px solid ${border}`, background: 'transparent', color: text, cursor: 'pointer', fontSize: 11, fontWeight: 600 }}>💾 Export</button>
        </div>
      </header>

      {/* Main */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        
        {/* Sidebar */}
        <aside style={{ width: 200, background: surface, borderRight: `1px solid ${border}`, padding: 16, overflowY: 'auto' }}>
          <div style={{ fontSize: 10, color: muted, fontWeight: 700, letterSpacing: 2, marginBottom: 8 }}>PROTOCOLS</div>
          {PROTOCOLS.map(p => (
            <button key={p.name} onClick={() => setFilter(p.name)} style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '8px 10px', borderRadius: 6, border: 'none', cursor: 'pointer', marginBottom: 2, background: filter === p.name ? `${p.color}15` : 'transparent', color: filter === p.name ? p.color : muted, fontWeight: filter === p.name ? 600 : 400, textAlign: 'left' as const }}>
              <span>{p.icon}</span><span>{p.name}</span>
            </button>
          ))}
          <div style={{ fontSize: 10, color: muted, fontWeight: 700, letterSpacing: 2, margin: '16px 0 8px' }}>SEARCH</div>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="IP, protocol..." style={{ width: '100%', padding: '8px 10px', background: border, border: 'none', borderRadius: 6, color: text, fontSize: 12, outline: 'none' }} />
          <div style={{ fontSize: 10, color: muted, fontWeight: 700, letterSpacing: 2, margin: '16px 0 8px' }}>STATS</div>
          <div style={{ fontSize: 11 }}>
            {['HTTP', 'HTTPS', 'DNS'].map(proto => {
              const color = PROTOCOLS.find(x => x.name === proto)?.color || muted;
              const count = packets.filter(p => p.protocol === proto).length;
              return (
                <div key={proto} style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color }}><span>{proto}</span><span>{count}</span></div>
                  <div style={{ height: 3, background: border, borderRadius: 2, marginTop: 4, overflow: 'hidden' }}>
                    <div style={{ height: '100%', background: color, width: `${(count / Math.max(packets.length, 1)) * 100}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        {/* Packets */}
        <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '8px 16px', background: surface, borderBottom: `1px solid ${border}`, display: 'flex', gap: 16, fontSize: 10, color: muted, fontWeight: 700 }}>
            <span style={{ width: 80 }}>TIME</span>
            <span style={{ width: 130 }}>SOURCE</span>
            <span style={{ width: 130 }}>DESTINATION</span>
            <span style={{ width: 70 }}>PROTO</span>
            <span style={{ width: 60 }}>SIZE</span>
            <span>INFO</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {filtered.slice(0, 100).map((p, i) => {
              const proto = PROTOCOLS.find(x => x.name === p.protocol) || PROTOCOLS[0];
              const isThreat = p.is_threat || BLACKLIST.includes(p.src_ip);
              return (
                <div key={p.id} onClick={() => setSelected(p)} style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '8px 16px', cursor: 'pointer', borderBottom: `1px solid ${border}`, background: selected?.id === p.id ? 'rgba(88, 166, 255, 0.1)' : isThreat ? 'rgba(248, 81, 73, 0.05)' : 'transparent', borderLeft: isThreat ? '3px solid #f85149' : '3px solid transparent' }}>
                  <span style={{ width: 80, color: muted, fontSize: 11 }}>{new Date(p.timestamp).toLocaleTimeString()}</span>
                  <span style={{ width: 130, fontFamily: 'monospace', fontSize: 12, color: isThreat ? '#fca5a5' : text }}>{p.src_ip}</span>
                  <span style={{ width: 130, fontFamily: 'monospace', fontSize: 12, color: muted }}>{p.dst_ip}</span>
                  <span style={{ background: `${proto.color}22`, color: proto.color, padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, width: 50, textAlign: 'center' }}>{p.protocol}</span>
                  <span style={{ width: 60, color: muted, fontSize: 11 }}>{p.size}B</span>
                  <span style={{ color: muted, fontSize: 11, flex: 1 }}>{p.plain_english || 'Network traffic'}</span>
                  {isThreat && <span style={{ background: '#f85149', color: '#fff', padding: '2px 6px', borderRadius: 4, fontSize: 9, fontWeight: 700 }}>⚠️</span>}
                </div>
              );
            })}
          </div>
        </main>

        {/* Details */}
        {selected && (
          <aside style={{ width: 320, background: surface, borderLeft: `1px solid ${border}`, padding: 16, overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span style={{ fontSize: 10, color: muted, fontWeight: 700, letterSpacing: 2 }}>PACKET DETAILS</span>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: muted, cursor: 'pointer' }}>✕</button>
            </div>
            <div style={{ background: border, borderRadius: 8, padding: 12, marginBottom: 12 }}>
              {[['Protocol', selected.protocol], ['Source', `${selected.src_ip}:${selected.src_port}`], ['Destination', `${selected.dst_ip}:${selected.dst_port}`], ['Size', `${selected.size} bytes`], ['Time', new Date(selected.timestamp).toLocaleTimeString()]].map(([k, v]) => (
                <div key={k as string} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${surface}` }}>
                  <span style={{ color: muted, fontSize: 11 }}>{k}</span>
                  <span style={{ fontSize: 11 }}>{v}</span>
                </div>
              ))}
            </div>
            <div style={{ background: 'rgba(88, 166, 255, 0.1)', borderRadius: 8, padding: 12, marginBottom: 12, border: '1px solid rgba(88, 166, 255, 0.2)' }}>
              <div style={{ fontSize: 10, color: '#58a6ff', fontWeight: 700, marginBottom: 6 }}>💡 PLAIN ENGLISH</div>
              <div style={{ fontSize: 11, color: '#bfdbfe', lineHeight: 1.6 }}>{selected.plain_english || `📡 ${selected.protocol} traffic from ${selected.src_ip} to ${selected.dst_ip}`}</div>
            </div>
            <button onClick={() => setSearch(selected.src_ip)} style={{ width: '100%', padding: 10, borderRadius: 8, border: 'none', background: 'linear-gradient(135deg, #58a6ff, #a371f7)', color: '#fff', fontWeight: 700, fontSize: 11, cursor: 'pointer' }}>🔍 Investigate {selected.src_ip}</button>
          </aside>
        )}
      </div>

      {/* Status Bar */}
      <footer style={{ background: surface, borderTop: `1px solid ${border}`, padding: '8px 20px', display: 'flex', alignItems: 'center', gap: 16, fontSize: 11, color: muted }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><div style={{ width: 6, height: 6, borderRadius: '50%', background: '#3fb950' }} /> Running</span>
        <span>│</span>
        <span>{hosts.length} hosts</span>
        <span>│</span>
        <span>{packets.length.toLocaleString()} packets</span>
        <span style={{ marginLeft: 'auto' }}>🐉 PacketWyrm v1.0.0</span>
      </footer>

      <style jsx global>{` * { box-sizing: border-box; margin: 0; padding: 0; } ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: ${bg}; } ::-webkit-scrollbar-thumb { background: ${border}; border-radius: 3px; } `}</style>
    </div>
  );
}
