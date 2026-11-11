import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import multer from 'multer';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, open, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Job from './models/Job.js';

const here = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(here, '.env') });
const uploadDir = path.resolve(here, process.env.UPLOAD_DIR || './uploads');
const enginePath = path.resolve(here, process.env.DPI_ENGINE_PATH || '../dpi_engine.exe');
const dumpcapPath = process.env.DUMPCAP_PATH || (process.platform === 'win32' && existsSync('C:/Program Files/Wireshark/dumpcap.exe')
  ? 'C:/Program Files/Wireshark/dumpcap.exe' : 'dumpcap');
const maxUploadBytes = Math.max(1, Number(process.env.MAX_UPLOAD_MB || 100)) * 1024 * 1024;
const maxWorkers = Math.min(4, Math.max(1, Number(process.env.MAX_WORKERS || 1)));
const engineTimeoutMs = Math.max(30_000, Number(process.env.ENGINE_TIMEOUT_MS || 600_000));
const supportedApps = [
  'Google', 'YouTube', 'Facebook', 'Instagram', 'Twitter/X', 'Netflix', 'Amazon',
  'Microsoft', 'Apple', 'WhatsApp', 'Telegram', 'TikTok', 'Spotify', 'Zoom', 'Discord', 'GitHub'
];
const appSet = new Set(supportedApps);
const queue = [];
const captures = new Map();
let activeWorkers = 0;

const app = express();
app.disable('x-powered-by');
app.use(cors({ origin: (process.env.WEB_ORIGIN || 'http://localhost:5173').split(',').map((value) => value.trim()) }));
app.use(express.json({ limit: '32kb' }));

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: maxUploadBytes, files: 1 },
  fileFilter: (_req, file, callback) => {
    if (path.extname(file.originalname).toLowerCase() !== '.pcap') {
      const error = new Error('Upload a classic .pcap file.');
      error.statusCode = 400;
      callback(error);
      return;
    }
    callback(null, true);
  }
});

function publicJob(job) {
  const value = job.toObject ? job.toObject() : job;
  return {
    id: String(value._id),
    originalName: value.originalName,
    fileSize: value.fileSize,
    status: value.status,
    rules: value.rules,
    stats: value.stats,
    error: value.error,
    createdAt: value.createdAt,
    startedAt: value.startedAt,
    completedAt: value.completedAt,
    downloadUrl: value.status === 'completed' ? `/api/jobs/${value._id}/download` : null
  };
}

function parseStats(output) {
  const read = (label) => {
    const match = output.match(new RegExp(`║\\s*${label}:\\s*([\\d,]+)`, 'i'));
    return match ? Number(match[1].replaceAll(',', '')) : 0;
  };
  return {
    totalPackets: read('Total Packets'),
    totalBytes: read('Total Bytes'),
    forwardedPackets: read('Forwarded'),
    droppedPackets: read('Dropped/Blocked'),
    tcpPackets: read('TCP Packets'),
    udpPackets: read('UDP Packets')
  };
}

function normalizeRules(raw = {}) {
  const blockApps = [...new Set((Array.isArray(raw.blockApps) ? raw.blockApps : []).map(String))];
  const blockDomains = [...new Set((Array.isArray(raw.blockDomains) ? raw.blockDomains : []).map(String))];
  const blockIps = [...new Set((Array.isArray(raw.blockIps) ? raw.blockIps : []).map(String))];
  const blockPorts = [...new Set((Array.isArray(raw.blockPorts) ? raw.blockPorts : []).map(String))];
  const loadBalancers = Number(raw.loadBalancers ?? 2);
  const fastPathsPerBalancer = Number(raw.fastPathsPerBalancer ?? 2);
  if (blockApps.some((value) => !appSet.has(value)) || blockDomains.some((value) =>
    !/^(\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(value)) ||
    blockIps.some((value) => !/^(\d{1,3}\.){3}\d{1,3}$/.test(value) || value.split('.').some((part) => Number(part) > 255)) ||
    blockPorts.some((value) => !/^\d{1,5}$/.test(value) || Number(value) > 65535) ||
    !Number.isInteger(loadBalancers) || !Number.isInteger(fastPathsPerBalancer) ||
    loadBalancers < 1 || loadBalancers > 8 || fastPathsPerBalancer < 1 || fastPathsPerBalancer > 8 ||
    loadBalancers * fastPathsPerBalancer > 32) throw new Error('One or more rules or worker settings are invalid.');
  return { blockApps, blockDomains, blockIps, blockPorts: blockPorts.map(Number), loadBalancers, fastPathsPerBalancer };
}

function runCaptureTool(args, timeoutMs = 15_000) {
  return new Promise((resolve) => {
    const child = spawn(dumpcapPath, args, { windowsHide: true, shell: false });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => { child.kill(); resolve({ code: -1, stdout, stderr: 'Capture tool timed out.' }); }, timeoutMs);
    child.stdout.on('data', (chunk) => { stdout = (stdout + chunk.toString()).slice(-32 * 1024); });
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-32 * 1024); });
    child.on('error', (error) => { clearTimeout(timer); resolve({ code: -1, stdout, stderr: error.code === 'ENOENT' ? 'Wireshark dumpcap was not found. Install Wireshark with Npcap, or set DUMPCAP_PATH in backend/.env.' : error.message }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

async function finishCapture(session) {
  if (session.finishPromise) return session.finishPromise;
  session.finishPromise = (async () => {
    const valid = await validatePcap(session.filePath).catch(() => false);
    if (!valid) {
      const fileInfo = await stat(session.filePath).catch(() => null);
      await unlink(session.filePath).catch(() => {});
      session.status = 'failed';
      const hint = 'Confirm the selected Wi-Fi interface is the active adapter, generate traffic during capture, and check that Npcap is installed and permitted to capture.';
      throw new Error(session.error || (fileInfo?.size > 24
        ? `The capture file has no complete readable packet. ${hint}`
        : `No packets reached the capture file. ${hint}`));
    }
    const fileInfo = await stat(session.filePath);
    const id = randomUUID().replaceAll('-', '');
    const job = await Job.create({
      originalName: `live-${session.interfaceName.replace(/[^a-z0-9_-]/gi, '_')}-${new Date(session.startedAt).toISOString().replace(/[:.]/g, '-')}.pcap`,
      inputName: session.fileName,
      outputName: `${id}-filtered.pcap`,
      fileSize: fileInfo.size,
      rules: session.rules
    });
    queue.push(String(job._id));
    void pumpQueue();
    session.status = 'completed';
    session.job = publicJob(job);
    const cleanupTimer = setTimeout(() => captures.delete(session.id), 10 * 60 * 1000);
    cleanupTimer.unref();
    return publicJob(job);
  })();
  return session.finishPromise;
}

function runEngine(job) {
  return new Promise((resolve) => {
    const inputPath = path.join(uploadDir, job.inputName);
    const outputPath = path.join(uploadDir, job.outputName);
    const args = [inputPath, outputPath];
    for (const value of job.rules.blockApps) args.push('--block-app', value);
    for (const value of job.rules.blockDomains) args.push('--block-domain', value);
    for (const value of job.rules.blockIps) args.push('--block-ip', value);
    for (const value of job.rules.blockPorts) args.push('--block-port', String(value));
    args.push('--lbs', String(job.rules.loadBalancers), '--fps', String(job.rules.fastPathsPerBalancer));

    const child = spawn(enginePath, args, { windowsHide: true, shell: false });
    let report = '';
    let errorOutput = '';
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, engineTimeoutMs);
    child.stdout.on('data', (chunk) => { report = (report + chunk.toString()).slice(-64 * 1024); });
    child.stderr.on('data', (chunk) => { errorOutput = (errorOutput + chunk.toString()).slice(-8 * 1024); });
    child.on('error', (error) => { clearTimeout(timer); resolve({ code: -1, error: error.message, report }); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, error: timedOut ? `Engine exceeded the ${Math.round(engineTimeoutMs / 1000)} second time limit.` : errorOutput.trim(), report });
    });
  });
}

async function pumpQueue() {
  while (activeWorkers < maxWorkers && queue.length) {
    const id = queue.shift();
    activeWorkers += 1;
    void (async () => {
      const job = await Job.findById(id);
      if (!job || job.status !== 'queued') return;
      job.status = 'running';
      job.startedAt = new Date();
      await job.save();
      const result = await runEngine(job);
      job.completedAt = new Date();
      job.stats = parseStats(result.report);
      if (result.code === 0) {
        job.status = 'completed';
        job.error = '';
      } else {
        job.status = 'failed';
        job.error = result.error || `Engine exited with code ${result.code}.`;
        await unlink(path.join(uploadDir, job.outputName)).catch(() => {});
      }
      await job.save();
      await unlink(path.join(uploadDir, job.inputName)).catch(() => {});
    })().catch(async (error) => {
      const job = await Job.findById(id).catch(() => null);
      if (job) {
        job.status = 'failed';
        job.error = error.message;
        job.completedAt = new Date();
        await job.save().catch(() => {});
        await unlink(path.join(uploadDir, job.inputName)).catch(() => {});
        await unlink(path.join(uploadDir, job.outputName)).catch(() => {});
      }
    }).finally(() => {
      activeWorkers -= 1;
      void pumpQueue();
    });
  }
}

async function validatePcap(filePath) {
  const handle = await open(filePath, 'r');
  try {
    const magic = Buffer.alloc(4);
    const { bytesRead } = await handle.read(magic, 0, 4, 0);
    const validMagic = bytesRead === 4 && (
      magic.equals(Buffer.from([0xd4, 0xc3, 0xb2, 0xa1])) ||
      magic.equals(Buffer.from([0xa1, 0xb2, 0xc3, 0xd4])) ||
      magic.equals(Buffer.from([0x4d, 0x3c, 0xb2, 0xa1])) ||
      magic.equals(Buffer.from([0xa1, 0xb2, 0x3c, 0x4d]))
    );
    if (!validMagic) return false;
    const fileInfo = await handle.stat();
    if (fileInfo.size < 40) return false; // 24-byte global header plus one packet header and data
    const packetHeader = Buffer.alloc(16);
    const read = await handle.read(packetHeader, 0, 16, 24);
    if (read.bytesRead !== 16) return false;
    const littleEndian = magic[0] === 0xd4 || magic[0] === 0x4d;
    const includedLength = littleEndian ? packetHeader.readUInt32LE(8) : packetHeader.readUInt32BE(8);
    return includedLength > 0 && includedLength <= 65535 && fileInfo.size >= 40 + includedLength;
  } finally {
    await handle.close();
  }
}

async function updateCaptureProgress(session) {
  try {
    const handle = await open(session.filePath, 'r');
    try {
      const info = await handle.stat();
      session.bytesCaptured = info.size;
      if (info.size < 24) return;
      if (session.packetOffset === undefined) {
        const magic = Buffer.alloc(4);
        const first = await handle.read(magic, 0, 4, 0);
        if (first.bytesRead !== 4) return;
        if (magic.equals(Buffer.from([0xd4, 0xc3, 0xb2, 0xa1])) || magic.equals(Buffer.from([0x4d, 0x3c, 0xb2, 0xa1]))) session.packetLittleEndian = true;
        else if (magic.equals(Buffer.from([0xa1, 0xb2, 0xc3, 0xd4])) || magic.equals(Buffer.from([0xa1, 0xb2, 0x3c, 0x4d]))) session.packetLittleEndian = false;
        else return;
        session.packetOffset = 24;
        session.packetsCaptured = 0;
      }
      const header = Buffer.alloc(16);
      while (session.bytesCaptured - session.packetOffset >= 16) {
        const read = await handle.read(header, 0, 16, session.packetOffset);
        if (read.bytesRead !== 16) break;
        const includedLength = session.packetLittleEndian ? header.readUInt32LE(8) : header.readUInt32BE(8);
        if (!includedLength || includedLength > 65535 || session.bytesCaptured - session.packetOffset < 16 + includedLength) break;
        session.packetOffset += 16 + includedLength;
        session.packetsCaptured += 1;
      }
    } finally { await handle.close(); }
  } catch { /* dumpcap may not have created its output file yet */ }
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, database: mongoose.connection.readyState === 1, engineConfigured: existsSync(enginePath) });
});

app.get('/api/apps', (_req, res) => res.json({ apps: supportedApps }));

app.get('/api/capture/interfaces', async (_req, res) => {
  const result = await runCaptureTool(['-D']);
  if (result.code !== 0) return res.status(503).json({ error: result.stderr || 'Could not list capture interfaces.' });
  const interfaces = result.stdout.split(/\r?\n/).map((line) => {
    const match = line.match(/^\s*(\d+)\.\s+(.+?)(?:\s+\((.*)\))?\s*$/);
    return match ? { id: match[1], name: match[3] ? `${match[2]} (${match[3]})` : match[2] } : null;
  }).filter(Boolean);
  res.json({ interfaces });
});

app.post('/api/capture/start', async (req, res) => {
  if ([...captures.values()].some((capture) => ['capturing', 'stopping'].includes(capture.status))) return res.status(409).json({ error: 'A live capture is already running. Stop it before starting another.' });
  const interfaceId = String(req.body?.interfaceId || '');
  if (!/^\d{1,3}$/.test(interfaceId)) return res.status(400).json({ error: 'Choose a valid network interface.' });
  let rules;
  try { rules = normalizeRules(req.body?.rules || {}); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  const listed = await runCaptureTool(['-D']);
  if (listed.code !== 0) return res.status(503).json({ error: listed.stderr || 'Could not access capture interfaces.' });
  const iface = listed.stdout.split(/\r?\n/).find((line) => new RegExp(`^\\s*${interfaceId}\\.`).test(line));
  if (!iface) return res.status(400).json({ error: 'That capture interface is no longer available. Refresh the interface list.' });
  const nameMatch = iface.match(/^\s*\d+\.\s+(.+?)(?:\s+\((.*)\))?\s*$/);
  const interfaceName = nameMatch ? (nameMatch[2] ? `${nameMatch[1]} (${nameMatch[2]})` : nameMatch[1]) : `Interface ${interfaceId}`;
  const durationSeconds = Number(req.body?.durationSeconds || 60);
  if (![15, 30, 60, 120, 300, 600, 900].includes(durationSeconds)) return res.status(400).json({ error: 'Choose a supported capture duration.' });
  const id = randomUUID();
  const fileName = `${id}.pcap`;
  const filePath = path.join(uploadDir, fileName);
  const child = spawn(dumpcapPath, ['-q', '-i', interfaceId, '-w', filePath, '-F', 'pcap', '-a', `duration:${durationSeconds}`, '-a', `filesize:${Math.floor(maxUploadBytes / 1024)}`], { windowsHide: true, shell: false });
  const session = { id, child, fileName, filePath, interfaceName, rules, durationSeconds, startedAt: new Date(), status: 'capturing', error: '', closePromise: null, packetsCaptured: 0, bytesCaptured: 0 };
  session.closePromise = new Promise((resolve) => { session.closeResolve = resolve; });
  captures.set(id, session);
  child.stderr.on('data', (chunk) => { session.stderr = (session.stderr || '').concat(chunk.toString()).slice(-4000); });
  child.on('error', (error) => {
    session.error = error.code === 'ENOENT' ? 'Wireshark dumpcap was not found. Install Wireshark with Npcap, or set DUMPCAP_PATH in backend/.env.' : error.message;
    session.closeResolve(-1);
  });
  child.on('close', (code) => {
    session.closeResolve(code);
    if (code === 0) void finishCapture(session).catch((error) => {
      session.error = error.message;
      session.status = 'failed';
      const cleanupTimer = setTimeout(() => captures.delete(session.id), 10 * 60 * 1000);
      cleanupTimer.unref();
    });
    else {
      session.status = 'failed';
      session.error ||= session.stderr?.trim() || 'Capture stopped unexpectedly. Check that Npcap is installed and the selected interface is available.';
      void unlink(session.filePath).catch(() => {});
      const cleanupTimer = setTimeout(() => captures.delete(session.id), 10 * 60 * 1000);
      cleanupTimer.unref();
    }
  });
  res.status(202).json({ capture: { id, interfaceName, startedAt: session.startedAt } });
});

app.get('/api/capture/:id', async (req, res) => {
  const session = captures.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Live capture was not found.' });
  if (session.status === 'capturing') await updateCaptureProgress(session);
  res.json({ capture: { id: session.id, interfaceName: session.interfaceName, startedAt: session.startedAt, status: session.status, error: session.error, packetsCaptured: session.packetsCaptured || 0, bytesCaptured: session.bytesCaptured || 0, job: session.job || null } });
});

app.get('/api/jobs', async (req, res, next) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 30));
    const jobs = await Job.find().sort({ createdAt: -1 }).limit(limit);
    res.json({ jobs: jobs.map(publicJob) });
  } catch (error) { next(error); }
});

app.get('/api/jobs/:id', async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid job id.' });
    const job = await Job.findById(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    res.json({ job: publicJob(job) });
  } catch (error) { next(error); }
});

app.post('/api/jobs', upload.single('pcap'), async (req, res, next) => {
  const filePath = req.file?.path;
  try {
    if (!req.file) return res.status(400).json({ error: 'Choose a PCAP file to analyze.' });
    if (!await validatePcap(filePath)) {
      await unlink(filePath).catch(() => {});
      return res.status(400).json({ error: 'The file header is not a supported classic PCAP capture.' });
    }
    let rules;
    try { rules = normalizeRules(JSON.parse(req.body.rules || '{}')); }
    catch (error) {
      await unlink(filePath).catch(() => {});
      return res.status(400).json({ error: error.message === 'Unexpected end of JSON input' ? 'Rules must be valid JSON.' : error.message });
    }

    const id = randomUUID().replaceAll('-', '');
    const job = await Job.create({
      originalName: path.basename(req.file.originalname),
      inputName: req.file.filename,
      outputName: `${id}-filtered.pcap`,
      fileSize: req.file.size,
      rules
    });
    queue.push(String(job._id));
    void pumpQueue();
    res.status(202).json({ job: publicJob(job) });
  } catch (error) {
    if (filePath) await unlink(filePath).catch(() => {});
    next(error);
  }
});

app.get('/api/jobs/:id/download', async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid job id.' });
    const job = await Job.findById(req.params.id);
    if (!job || job.status !== 'completed') return res.status(404).json({ error: 'Completed output not found.' });
    const outputPath = path.join(uploadDir, job.outputName);
    res.download(outputPath, `${path.parse(job.originalName).name}-filtered.pcap`, (error) => {
      if (error && !res.headersSent) next(error);
    });
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  const status = error.statusCode || (error instanceof multer.MulterError ? (error.code === 'LIMIT_FILE_SIZE' ? 413 : 400) : 500);
  res.status(status).json({ error: status === 500 ? 'The request could not be completed.' : error.message });
});

await mkdir(uploadDir, { recursive: true });
await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/packet_analyzer');
await Job.updateMany({ status: { $in: ['queued', 'running'] } }, {
  $set: { status: 'failed', error: 'API restarted before this job completed.', completedAt: new Date() }
});
const port = Number(process.env.PORT || 4000);
const host = process.env.HOST || '127.0.0.1';
const server = app.listen(port, host, () => console.log(`Packet Analyzer API listening at http://${host}:${port}`));

async function shutdown() {
  for (const session of captures.values()) {
    session.child.kill('SIGINT');
  }
  server.close();
  await mongoose.disconnect();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
