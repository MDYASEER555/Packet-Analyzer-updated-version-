import { useCallback, useEffect, useMemo, useState } from 'react';

const appOptions = ['Google', 'YouTube', 'Facebook', 'Instagram', 'Twitter/X', 'Netflix', 'Amazon', 'Microsoft', 'Apple', 'WhatsApp', 'Telegram', 'TikTok', 'Spotify', 'Zoom', 'Discord', 'GitHub'];
const initialRules = { blockApps: [], blockDomains: '', blockIps: '', blockPorts: '', loadBalancers: 2, fastPathsPerBalancer: 2 };

function bytes(value = 0) {
  if (!value) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}
function date(value) {
  return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—';
}
async function request(url, options) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}
function StatusPill({ status }) {
  const label = { queued: 'Queued', running: 'Analyzing', completed: 'Complete', failed: 'Failed' }[status] || status;
  return <span className={`status-pill ${status}`}><i />{label}</span>;
}

export default function App() {
  const [jobs, setJobs] = useState([]);
  const [rules, setRules] = useState(initialRules);
  const [file, setFile] = useState(null);
  const [inputMode, setInputMode] = useState('saved');
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [captureDuration, setCaptureDuration] = useState(60);
  const [capture, setCapture] = useState(null);
  const [captureElapsed, setCaptureElapsed] = useState(0);
  const [loadingInterfaces, setLoadingInterfaces] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [service, setService] = useState({ api: false, database: false, engine: false });

  const refresh = useCallback(async () => {
    try {
      const [jobData, health] = await Promise.all([request('/api/jobs'), request('/api/health')]);
      setJobs(jobData.jobs);
      setService({ api: true, database: health.database, engine: health.engineConfigured });
    } catch { setService({ api: false, database: false, engine: false }); }
  }, []);
  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 3500);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const loadInterfaces = useCallback(async () => {
    setLoadingInterfaces(true);
    try {
      const result = await request('/api/capture/interfaces');
      setInterfaces(result.interfaces);
      setSelectedInterface((current) => result.interfaces.some((item) => item.id === current) ? current : (result.interfaces[0]?.id || ''));
    } catch (error) {
      setInterfaces([]);
      setNotice({ kind: 'error', text: error.message });
    } finally { setLoadingInterfaces(false); }
  }, []);

  useEffect(() => {
    if (inputMode === 'live') loadInterfaces();
  }, [inputMode, loadInterfaces]);

  useEffect(() => {
    if (!capture) return undefined;
    const timer = window.setInterval(async () => {
      setCaptureElapsed(Math.floor((Date.now() - new Date(capture.startedAt).getTime()) / 1000));
      try {
        const result = await request(`/api/capture/${capture.id}`);
        setCapture((current) => current?.id === capture.id ? { ...current, ...result.capture } : current);
        if (result.capture.status === 'failed') {
          setCapture(null);
          setNotice({ kind: 'error', text: result.capture.error || 'The live capture stopped unexpectedly.' });
        } else if (result.capture.job) {
          setCapture(null);
          setNotice({ kind: 'success', text: `Live capture queued for analysis: ${result.capture.job.originalName}.` });
          await refresh();
        }
      } catch (error) {
        if (error.message.includes('not found')) setCapture(null);
      }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [capture, refresh]);

  const active = useMemo(() => jobs.filter((job) => ['queued', 'running'].includes(job.status)).length, [jobs]);
  const totals = useMemo(() => jobs.reduce((value, job) => ({
    packets: value.packets + (job.stats?.totalPackets || 0),
    dropped: value.dropped + (job.stats?.droppedPackets || 0),
    bytes: value.bytes + (job.stats?.totalBytes || 0)
  }), { packets: 0, dropped: 0, bytes: 0 }), [jobs]);
  function updateRule(key, value) { setRules((current) => ({ ...current, [key]: value })); }
  function toggleApp(name) {
    setRules((current) => ({ ...current, blockApps: current.blockApps.includes(name)
      ? current.blockApps.filter((item) => item !== name) : [...current.blockApps, name] }));
  }
  function currentRules() {
    return {
      blockApps: rules.blockApps,
      blockDomains: rules.blockDomains.split(/[\n,]/).map((item) => item.trim()).filter(Boolean),
      blockIps: rules.blockIps.split(/[\n,]/).map((item) => item.trim()).filter(Boolean),
      blockPorts: rules.blockPorts.split(/[\n,]/).map((item) => item.trim()).filter(Boolean),
      loadBalancers: Number(rules.loadBalancers), fastPathsPerBalancer: Number(rules.fastPathsPerBalancer)
    };
  }
  async function submit(event) {
    event.preventDefault();
    if (!file) { setNotice({ kind: 'error', text: 'Choose a .pcap capture first.' }); return; }
    setBusy(true); setNotice(null);
    const form = new FormData();
    form.append('rules', JSON.stringify(currentRules()));
    form.append('pcap', file);
    try {
      const result = await request('/api/jobs', { method: 'POST', body: form });
      setNotice({ kind: 'success', text: `Analysis queued for ${result.job.originalName}.` });
      setFile(null); event.target.reset(); await refresh();
    } catch (error) { setNotice({ kind: 'error', text: error.message }); }
    finally { setBusy(false); }
  }
  async function startLiveCapture() {
    if (!selectedInterface) { setNotice({ kind: 'error', text: 'Choose a network interface first.' }); return; }
    setBusy(true); setNotice(null);
    try {
      const result = await request('/api/capture/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interfaceId: selectedInterface, durationSeconds: Number(captureDuration), rules: currentRules() }) });
      setCapture(result.capture);
      setCaptureElapsed(0);
      setNotice({ kind: 'success', text: `Capturing on ${result.capture.interfaceName} for ${captureDuration} seconds.` });
    } catch (error) { setNotice({ kind: 'error', text: error.message }); }
    finally { setBusy(false); }
  }
  const remaining = Math.max(0, captureDuration - captureElapsed);
  const elapsedLabel = `${Math.floor(remaining / 60).toString().padStart(2, '0')}:${(remaining % 60).toString().padStart(2, '0')}`;

  return <div className="app-shell">
    <header className="topbar">
      <a className="brand" href="#top" aria-label="Packet Analyzer home"><span className="brand-mark"><span /><span /><span /></span><span>PACKET<span className="brand-light"> / ANALYZER</span></span></a>
      <div className="topbar-right"><div className={`service-state ${service.api && service.database && service.engine ? 'online' : 'offline'}`} title={`API ${service.api ? 'ready' : 'offline'} · MongoDB ${service.database ? 'ready' : 'offline'} · Engine ${service.engine ? 'ready' : 'missing'}`}><span className="pulse-dot" />{service.api && service.database && service.engine ? 'SYSTEM ONLINE' : 'CHECK SETUP'}</div><span className="version-tag">DPI ENGINE <b>1.0</b></span></div>
    </header>
    <main id="top" className="main-content">
      <section className="hero">
        <div className="hero-copy"><div className="eyebrow"><span className="eyebrow-line" /> TRAFFIC LAB / LIVE + SAVED ANALYSIS</div><h1>See what’s<br /><em>moving</em> through.</h1><p>Capture traffic live from a network interface or inspect a saved PCAP. Apply your rules and get a filtered capture back through your DPI engine.</p><div className="hero-meta"><span className="meta-icon">⌁</span> PCAP WORKSPACE <span className="meta-sep">/</span> SESSION OVERVIEW</div></div>
        <div className="hero-visual" aria-hidden="true"><div className="orbit orbit-outer" /><div className="orbit orbit-inner" /><div className="visual-core"><span className="core-ring" /><span className="core-center">↗</span></div><span className="orbit-label label-a">FLOW <b>01</b></span><span className="orbit-label label-b">DPI <b>ON</b></span><span className="orbit-node node-a" /><span className="orbit-node node-b" /><span className="orbit-node node-c" /><div className="visual-caption">PACKET<br />INSPECTION <span>● LIVE</span></div></div>
      </section>
      <section className="metric-grid" aria-label="Workspace totals">
        <article className="metric-card"><div className="metric-head"><span>CAPTURES</span><span className="metric-index">01</span></div><div className="metric-value">{jobs.length.toString().padStart(2, '0')}<small> jobs</small></div><div className="metric-foot"><span className="metric-symbol cyan">◉</span> In this workspace</div></article>
        <article className="metric-card"><div className="metric-head"><span>PACKETS SCANNED</span><span className="metric-index">02</span></div><div className="metric-value">{totals.packets.toLocaleString()}<small> packets</small></div><div className="metric-foot"><span className="metric-symbol blue">↗</span> Across completed captures</div></article>
        <article className="metric-card"><div className="metric-head"><span>PACKETS DROPPED</span><span className="metric-index">03</span></div><div className="metric-value">{totals.dropped.toLocaleString()}<small> packets</small></div><div className="metric-foot"><span className="metric-symbol amber">⦸</span> By the analysis rules</div></article>
        <article className="metric-card metric-active"><div className="metric-head"><span>IN THE QUEUE</span><span className="metric-index">04</span></div><div className="metric-value">{active.toString().padStart(2, '0')}<small> active</small></div><div className="metric-foot"><span className="metric-symbol green">⌁</span> {active ? 'Engine is processing' : 'Ready for a capture'}</div></article>
      </section>
      <section className="workspace-grid">
        <form className="panel upload-panel" onSubmit={submit}>
          <div className="panel-heading"><div><div className="section-kicker">01 / NEW ANALYSIS</div><h2>Run a capture</h2></div><span className="heading-glyph">＋</span></div>
          <div className="mode-tabs" role="tablist" aria-label="Capture source"><button type="button" role="tab" aria-selected={inputMode === 'saved'} className={inputMode === 'saved' ? 'selected' : ''} onClick={() => setInputMode('saved')} disabled={Boolean(capture)}>SAVED PCAP</button><button type="button" role="tab" aria-selected={inputMode === 'live'} className={inputMode === 'live' ? 'selected' : ''} onClick={() => setInputMode('live')} disabled={Boolean(capture)}>LIVE CAPTURE</button></div>
          {inputMode === 'saved' ? <label className={`dropzone ${file ? 'has-file' : ''}`} htmlFor="pcap-file" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); setFile(event.dataTransfer.files?.[0] || null); }}><input id="pcap-file" type="file" accept=".pcap,application/vnd.tcpdump.pcap" onChange={(event) => setFile(event.target.files?.[0] || null)} /><span className="upload-icon">↑</span><strong>{file ? file.name : 'Drop your capture here'}</strong><span>{file ? `${bytes(file.size)} · Ready to analyze` : 'or click to browse your files'}</span><small>CLASSIC PCAP · UP TO 100 MB</small></label> : <div className="live-capture-box"><div className="live-capture-heading"><div><strong>{capture ? 'LIVE CAPTURE RUNNING' : 'Capture from this device'}</strong><span>{capture ? `${capture.interfaceName} · ${elapsedLabel} remaining · ${(capture.packetsCaptured || 0).toLocaleString()} packets · ${bytes(capture.bytesCaptured || 0)}` : 'Select an interface and how long to capture traffic.'}</span></div>{capture && <span className="recording-dot" aria-label="Recording" />}</div><div className="interface-row"><select value={selectedInterface} onChange={(event) => setSelectedInterface(event.target.value)} disabled={Boolean(capture) || loadingInterfaces}><option value="">{loadingInterfaces ? 'Loading interfaces…' : interfaces.length ? 'Choose interface' : 'No interfaces found'}</option>{interfaces.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select><button className="refresh-button" type="button" onClick={loadInterfaces} disabled={loadingInterfaces || Boolean(capture)} aria-label="Refresh interfaces">↻</button></div><div className="duration-row"><label htmlFor="capture-duration">CAPTURE DURATION</label><select id="capture-duration" value={captureDuration} onChange={(event) => setCaptureDuration(Number(event.target.value))} disabled={Boolean(capture)}>{[[15,'15 seconds'],[30,'30 seconds'],[60,'1 minute'],[120,'2 minutes'],[300,'5 minutes'],[600,'10 minutes'],[900,'15 minutes']].map(([seconds,label]) => <option key={seconds} value={seconds}>{label}</option>)}</select></div><p className="capture-help">Requires Wireshark with Npcap installed. Packet counts update during capture. Rules filter the saved PCAP after capture ends.</p></div>}
          <div className="rule-section"><div className="subhead"><span>FILTER FROM CAPTURE</span><span className="optional-label">APPLIED TO PCAP</span></div><div className="app-chips">{appOptions.map((name) => <button type="button" key={name} className={`app-chip ${rules.blockApps.includes(name) ? 'selected' : ''}`} onClick={() => toggleApp(name)} aria-pressed={rules.blockApps.includes(name)}>{name}</button>)}</div></div>
          <div className="rule-inputs">
            <label><span>FILTER DOMAINS <small>COMMA OR LINE SEPARATED</small></span><textarea rows="2" value={rules.blockDomains} onChange={(event) => updateRule('blockDomains', event.target.value)} placeholder="example.com, *.social.example" /></label>
            <label><span>FILTER SOURCE IPs <small>COMMA OR LINE SEPARATED</small></span><textarea rows="2" value={rules.blockIps} onChange={(event) => updateRule('blockIps', event.target.value)} placeholder="192.168.1.25" /></label>
            <label><span>FILTER DESTINATION PORTS <small>0–65535 · COMMA OR LINE SEPARATED</small></span><textarea rows="1" value={rules.blockPorts} onChange={(event) => updateRule('blockPorts', event.target.value)} placeholder="53, 443" /></label>
          </div>
          <div className="worker-row"><label>Load balancers <input type="number" min="1" max="8" value={rules.loadBalancers} onChange={(event) => updateRule('loadBalancers', event.target.value)} /></label><span className="worker-times">×</span><label>Fast paths / balancer <input type="number" min="1" max="8" value={rules.fastPathsPerBalancer} onChange={(event) => updateRule('fastPathsPerBalancer', event.target.value)} /></label></div>
          {notice && <div className={`notice ${notice.kind}`} role="status">{notice.text}</div>}
          {inputMode === 'saved' ? <button className="run-button" type="submit" disabled={busy || !service.api || !service.database || !service.engine}><span>{busy ? 'SENDING TO QUEUE…' : 'START ANALYSIS'}</span><b>↗</b></button> : <button className="run-button" type="button" onClick={startLiveCapture} disabled={busy || Boolean(capture) || !service.api || !service.database || !service.engine || !selectedInterface}><span>{busy ? 'STARTING CAPTURE…' : capture ? `CAPTURE RUNNING · ${elapsedLabel}` : 'START LIVE CAPTURE'}</span><b>{capture ? '●' : '↗'}</b></button>}
          <div className="local-note"><span>◇</span> Files are processed by your local engine and are not sent to a cloud service.</div>
        </form>
        <section className="panel jobs-panel"><div className="panel-heading"><div><div className="section-kicker">02 / ACTIVITY</div><h2>Recent captures</h2></div><button className="refresh-button" type="button" onClick={refresh} aria-label="Refresh activity">↻</button></div>
          {jobs.length === 0 ? <div className="empty-state"><div className="empty-icon">⌁</div><h3>No captures yet</h3><p>Upload a PCAP or finish a live capture to start your first inspection session.</p></div> : <div className="job-list">{jobs.map((job) => <article className="job-card" key={job.id}>
            <div className="job-top"><div className="job-file-icon">PCAP</div><div className="job-name"><strong title={job.originalName}>{job.originalName}</strong><span>{bytes(job.fileSize)} <i>·</i> {date(job.createdAt)}</span></div><StatusPill status={job.status} /></div>
            {job.status === 'completed' && <div className="job-stats"><span><b>{job.stats.totalPackets.toLocaleString()}</b> packets</span><span><b>{job.stats.forwardedPackets.toLocaleString()}</b> retained</span><span className="dropped-stat"><b>{job.stats.droppedPackets.toLocaleString()}</b> filtered out</span><span><b>{bytes(job.stats.totalBytes)}</b> inspected</span></div>}
            {job.status === 'failed' && <div className="job-error">{job.error}</div>}
            <div className="job-bottom"><span>{job.rules.blockApps?.length || job.rules.blockDomains?.length || job.rules.blockIps?.length || job.rules.blockPorts?.length ? 'FILTER RULES APPLIED' : 'NO FILTERS'}</span>{job.downloadUrl && <a href={job.downloadUrl} className="download-link">DOWNLOAD FILTERED PCAP <b>↓</b></a>}</div>
          </article>)}</div>}
          <div className="queue-footer"><span className="footer-dot" /> AUTO-REFRESH EVERY 3.5 SECONDS <span>LOCAL QUEUE · {active} ACTIVE</span></div>
        </section>
      </section>
      <footer className="page-footer"><span>PACKET ANALYZER <b>·</b> DEEP PACKET INSPECTION</span><span>BUILT FOR CLEARER TRAFFIC.</span></footer>
    </main>
  </div>;
}
