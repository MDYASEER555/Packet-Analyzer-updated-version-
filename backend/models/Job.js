import mongoose from 'mongoose';

const jobSchema = new mongoose.Schema({
  originalName: { type: String, required: true },
  inputName: { type: String, required: true },
  outputName: { type: String, required: true },
  fileSize: { type: Number, required: true },
  status: {
    type: String,
    enum: ['queued', 'running', 'completed', 'failed'],
    default: 'queued',
    index: true
  },
  rules: {
    blockApps: { type: [String], default: [] },
    blockDomains: { type: [String], default: [] },
    blockIps: { type: [String], default: [] },
    blockPorts: { type: [Number], default: [] },
    loadBalancers: { type: Number, default: 2 },
    fastPathsPerBalancer: { type: Number, default: 2 }
  },
  stats: {
    totalPackets: { type: Number, default: 0 },
    totalBytes: { type: Number, default: 0 },
    forwardedPackets: { type: Number, default: 0 },
    droppedPackets: { type: Number, default: 0 },
    tcpPackets: { type: Number, default: 0 },
    udpPackets: { type: Number, default: 0 }
  },
  error: { type: String, default: '' },
  startedAt: Date,
  completedAt: Date
}, { timestamps: true });

export default mongoose.model('Job', jobSchema);
