/**
 * Offline TF.js URL Phishing Classifier Training Script
 *
 * Usage:
 *   node scripts/trainModel.js                              ← synthetic data only
 *   node scripts/trainModel.js --data ./dataset.csv         ← real CSV
 *   node scripts/trainModel.js --data ./dataset.csv --epochs 100 --output ./public/tfjs_model
 *
 * CSV format: url,label
 *   label = safe | suspicious | unsafe   (or 0 | 1 | 2)
 *
 * Dataset sources:
 *   - PhishTank:        https://phishtank.com/developer_info.php
 *   - Phishing.Database: https://github.com/mitchellkrogza/Phishing.Database
 *   - UCI ML Repo:      https://archive.ics.uci.edu/dataset/327/phishing+websites
 */

import * as tf from '@tensorflow/tfjs';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

// ─── Feature extraction (ported from mlService.ts) ────────────────────────────

const SUSPICIOUS_TLDS = new Set([
  'tk','ml','ga','cf','gq','xyz','top','work','date','men','loan',
  'download','win','bid','trade','webcam','review','science','party',
  'racing','click','link',
]);

const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'shorturl.at','rb.gy','tiny.cc','cutt.ly','s.id',
]);

const PHISHING_KW = [
  'login','signin','verify','secure','update','confirm','account',
  'password','credential','banking','paypal','refund','reward','prize',
  'winner','free','urgent','suspended','restrict','unlock','authenticate',
];

const TRUSTED_DOMAINS = new Set([
  'google.com','youtube.com','facebook.com','twitter.com','x.com',
  'instagram.com','linkedin.com','microsoft.com','apple.com','amazon.com',
  'github.com','stackoverflow.com','wikipedia.org','reddit.com',
  'whatsapp.com','telegram.org','discord.com','zoom.us','canva.com',
  'netflix.com','spotify.com','npmjs.com','react.dev',
  'uptm.edu.my','kptm.edu.my','edupage.org',
]);

function extractFeatures(url) {
  let u;
  try {
    u = new URL(url.startsWith('//') ? `https:${url}` : url);
  } catch {
    return {
      urlLength: 1, dotCount: 0, dashCount: 0, atSymbol: 1,
      isHttps: 0, isIp: 0, suspiciousTld: 1, isShortener: 0,
      pathLength: 1, keywordCount: 1, numericRatio: 0, hasPort: 1,
      subdomainDepth: 0, encodedChars: 1, cyrillicChars: 0,
      brandSpoof: 0, isTrusted: 0, domainLength: 1,
    };
  }

  const hostname = u.hostname.toLowerCase();
  const parts = hostname.split('.');
  const tld = parts[parts.length - 1];
  const regDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const path = u.pathname + u.search;

  const brands = ['paypal','facebook','instagram','twitter','linkedin',
                  'whatsapp','amazon','apple','microsoft','google','netflix'];
  const hasSpoof = brands.some(b =>
    hostname.includes(b) && !hostname.endsWith('.' + b) && !hostname.startsWith(b + '.')
  );

  return {
    urlLength: Math.min(url.length / 200, 1),
    dotCount: Math.min((hostname.match(/\./g) || []).length / 6, 1),
    dashCount: Math.min((hostname.match(/-/g) || []).length / 5, 1),
    atSymbol: url.includes('@') ? 1 : 0,
    isHttps: u.protocol === 'https:' ? 1 : 0,
    isIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
    suspiciousTld: SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    isShortener: SHORTENERS.has(regDomain) ? 1 : 0,
    pathLength: Math.min(path.length / 300, 1),
    keywordCount: Math.min(
      PHISHING_KW.filter(kw => path.toLowerCase().includes(kw) || hostname.includes(kw)).length / 5,
      1
    ),
    numericRatio: (hostname.match(/\d/g) || []).length / Math.max(hostname.length, 1),
    hasPort: u.port ? 1 : 0,
    subdomainDepth: Math.min(Math.max(parts.length - 2, 0) / 4, 1),
    encodedChars: /%[0-9a-fA-F]{2}/.test(hostname) ? 1 : 0,
    cyrillicChars: /[а-яА-Я]/.test(hostname) ? 1 : 0,
    brandSpoof: hasSpoof ? 1 : 0,
    isTrusted: TRUSTED_DOMAINS.has(hostname) ? 1 : 0,
    domainLength: Math.min(hostname.length / 60, 1),
  };
}

const LABEL_MAP = { safe: 0, suspicious: 1, unsafe: 2, '0': 0, '1': 1, '2': 2 };

function oneHot(label, numClasses = 3) {
  const vec = new Array(numClasses).fill(0);
  const idx = LABEL_MAP[label?.toLowerCase()?.trim()] ?? 1;
  vec[idx] = 1;
  return vec;
}

// ─── CSV loading ──────────────────────────────────────────────────────────────

async function loadCSV(filePath, maxSamples = Infinity) {
  const xs = [];
  const ys = [];
  let skipped = 0;

  const stream = fs.createReadStream(filePath, 'utf-8');
  const rl = createInterface({ input: stream });

  let header = true;
  for await (const line of rl) {
    if (header) { header = false; continue; }
    if (!line.trim()) continue;

    const parts = line.split(',');
    const url = parts[0]?.trim();
    const label = parts.slice(1).join(',').trim();

    if (!url || !label) { skipped++; continue; }

    const features = extractFeatures(url);
    xs.push(Object.values(features));
    ys.push(oneHot(label));

    if (xs.length >= maxSamples) break;
  }

  console.log(`  Loaded ${xs.length} samples${skipped > 0 ? ` (${skipped} skipped)` : ''}`);
  return { xs, ys };
}

// ─── Synthetic fallback ───────────────────────────────────────────────────────

function randomBetween(a, b) { return a + Math.random() * (b - a); }

function generateSyntheticSamples(n) {
  const xs = [];
  const ys = [];

  for (let i = 0; i < n; i++) {
    const isTrusted = Math.random() < 0.2 ? 1 : 0;
    const isIp = !isTrusted && Math.random() < 0.05 ? 1 : 0;
    const spoof = !isTrusted && !isIp && Math.random() < 0.08 ? 1 : 0;

    const f = {
      urlLength: randomBetween(0.05, isTrusted ? 0.3 : 0.9),
      dotCount: randomBetween(0, isTrusted ? 0.3 : 0.8),
      dashCount: randomBetween(0, 0.5),
      atSymbol: Math.random() < 0.03 ? 1 : 0,
      isHttps: isTrusted ? 1 : (Math.random() < 0.6 ? 1 : 0),
      isIp,
      suspiciousTld: !isTrusted && Math.random() < 0.15 ? 1 : 0,
      isShortener: !isTrusted && Math.random() < 0.1 ? 1 : 0,
      pathLength: randomBetween(0, 0.7),
      keywordCount: !isTrusted ? randomBetween(0, 0.6) : 0,
      numericRatio: randomBetween(0, 0.3),
      hasPort: Math.random() < 0.05 ? 1 : 0,
      subdomainDepth: randomBetween(0, isTrusted ? 0.25 : 0.75),
      encodedChars: !isTrusted && Math.random() < 0.1 ? 1 : 0,
      cyrillicChars: !isTrusted && Math.random() < 0.04 ? 1 : 0,
      brandSpoof: spoof ? 1 : 0,
      isTrusted,
      domainLength: randomBetween(0, isTrusted ? 0.4 : 0.9),
    };

    // Label via same rule as mlService.ts
    let label;
    if (isTrusted) label = [1, 0, 0];
    else if (isIp || spoof || f.atSymbol || f.cyrillicChars) label = [0, 0, 1];
    else {
      const risk =
        f.suspiciousTld * 0.25 + f.isShortener * 0.15 + f.dotCount * 0.15 +
        f.keywordCount * 0.20 + f.pathLength * 0.10 + f.encodedChars * 0.10 +
        (1 - f.isHttps) * 0.15 + f.hasPort * 0.10;
      if (risk >= 0.45) label = [0, 0, 1];
      else if (risk >= 0.20) label = [0, 1, 0];
      else label = [1, 0, 0];
    }

    xs.push(Object.values(f));
    ys.push(label);
  }
  return { xs, ys };
}

// ─── Model definition ─────────────────────────────────────────────────────────

function buildModel() {
  const input = tf.input({ shape: [18] });

  const x = tf.layers.dense({ units: 128, kernelInitializer: 'glorotUniform' }).apply(input);
  const b1 = tf.layers.batchNormalization().apply(x);
  const a1 = tf.layers.leakyReLU({ alpha: 0.1 }).apply(b1);
  const d1 = tf.layers.dropout({ rate: 0.3 }).apply(a1);

  const y = tf.layers.dense({ units: 64, kernelInitializer: 'glorotUniform' }).apply(d1);
  const b2 = tf.layers.batchNormalization().apply(y);
  const a2 = tf.layers.leakyReLU({ alpha: 0.1 }).apply(b2);
  const d2 = tf.layers.dropout({ rate: 0.3 }).apply(a2);

  const z = tf.layers.dense({ units: 32, kernelInitializer: 'glorotUniform' }).apply(d2);
  const b3 = tf.layers.batchNormalization().apply(z);
  const a3 = tf.layers.leakyReLU({ alpha: 0.1 }).apply(b3);
  const d3 = tf.layers.dropout({ rate: 0.2 }).apply(a3);

  const output = tf.layers.dense({ units: 3, activation: 'softmax' }).apply(d3);

  const m = tf.model({ inputs: input, outputs: output });
  m.compile({
    optimizer: tf.train.adam(0.001),
    loss: 'categoricalCrossentropy',
    metrics: ['accuracy'],
  });
  return m;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args = {};
  const raw = process.argv.slice(2);
  for (let i = 0; i < raw.length; i++) {
    if (raw[i].startsWith('--')) {
      args[raw[i].slice(2)] = raw[i + 1] && !raw[i + 1].startsWith('--') ? raw[i + 1] : true;
      if (args[raw[i].slice(2)] !== true) i++;
    }
  }

  const dataPath = args.data;
  const outputDir = args.output || path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..', 'public', 'tfjs_model'
  );
  const epochs = parseInt(args.epochs, 10) || 50;
  const batchSize = parseInt(args.batchSize, 10) || 32;
  const valSplit = parseFloat(args.valSplit) || 0.15;

  console.log('╔══════════════════════════════════════════╗');
  console.log('║   Campus Shield — TF.js Model Trainer   ║');
  console.log('╚══════════════════════════════════════════╝\n');

  // Load data
  let xs, ys;
  if (dataPath) {
    const fullPath = path.resolve(dataPath);
    if (!fs.existsSync(fullPath)) {
      console.error(`❌ Dataset not found: ${fullPath}`);
      process.exit(1);
    }
    console.log(`📂 Loading dataset: ${fullPath}`);
    const data = await loadCSV(fullPath);
    xs = data.xs;
    ys = data.ys;
    if (xs.length === 0) {
      console.error('❌ No valid samples found in CSV');
      process.exit(1);
    }
    console.log(`   Samples: ${xs.length} | Features: ${xs[0].length}`);
  } else {
    console.log('🧪 No --data provided. Generating synthetic dataset...');
    const syntheticSize = parseInt(args.synthetic, 10) || 5000;
    const data = generateSyntheticSamples(syntheticSize);
    xs = data.xs;
    ys = data.ys;
    console.log(`   Samples: ${xs.length} (synthetic)`);
  }

  // Count class distribution
  const dist = [0, 0, 0];
  for (const y of ys) {
    const idx = y.indexOf(1);
    if (idx >= 0) dist[idx]++;
  }
  console.log(`   Class distribution — SAFE: ${dist[0]}, SUSPICIOUS: ${dist[1]}, UNSAFE: ${dist[2]}`);

  // Build model
  console.log('\n🏗️  Building deep model (128→64→32→3)...');
  const model = buildModel();
  model.summary();

  // Train
  const xTensor = tf.tensor2d(xs);
  const yTensor = tf.tensor2d(ys);

  console.log(`\n🚀 Training for ${epochs} epochs (batch=${batchSize}, val_split=${valSplit})...\n`);

  const history = await model.fit(xTensor, yTensor, {
    epochs,
    batchSize,
    validationSplit: valSplit,
    shuffle: true,
    verbose: 1,
    callbacks: tf.callbacks.earlyStopping({ monitor: 'val_loss', patience: 7 }),
  });

  xTensor.dispose();
  yTensor.dispose();

  // Final metrics
  const finalLoss = history.history.loss.at(-1).toFixed(4);
  const finalAcc = (history.history.acc.at(-1) * 100).toFixed(2);
  const valLoss = history.history.val_loss.at(-1).toFixed(4);
  const valAcc = (history.history.val_acc.at(-1) * 100).toFixed(2);

  console.log(`\n📊 Results:`);
  console.log(`   Train Loss: ${finalLoss} | Train Acc: ${finalAcc}%`);
  console.log(`   Val Loss:   ${valLoss} | Val Acc:   ${valAcc}%`);

  // Save model manually (no native deps needed)
  fs.mkdirSync(outputDir, { recursive: true });

  const topology = model.toJSON();
  const weightTensors = model.getWeights();
  const weightData = await Promise.all(weightTensors.map(t => t.data()));
  const weightSpecs = weightTensors.map((t, i) => ({
    name: t.name.replace(/\//g, '_').replace(/:/g, '_'),
    shape: t.shape,
    dtype: t.dtype,
  }));

  // Collect all weight buffers into one shard
  const chunks = weightData.map(d => Buffer.from(d.buffer));
  const shardBuffer = Buffer.concat(chunks);

  // Offsets for each weight within the shard
  let offset = 0;
  const weightOffsets = chunks.map(c => {
    const off = offset;
    offset += c.length;
    return off;
  });

  const modelJson = {
    modelTopology: topology,
    weightsManifest: [{
      paths: ['group1-shard1of1.bin'],
      weights: weightSpecs.map((spec, i) => ({
        name: spec.name,
        shape: spec.shape,
        dtype: spec.dtype,
        offset: weightOffsets[i],
        size: chunks[i].length,
      })),
    }],
  };

  fs.writeFileSync(
    path.join(outputDir, 'model.json'),
    JSON.stringify(modelJson, null, 2)
  );
  fs.writeFileSync(path.join(outputDir, 'group1-shard1of1.bin'), shardBuffer);

  // Clean up tensors
  weightTensors.forEach(t => t.dispose());

  console.log(`\n💾 Model saved to: ${outputDir}/`);
  console.log(`   ├─ model.json`);
  console.log(`   └─ group1-shard1of1.bin`);
  console.log(`\n✅ Done! Deploy the 'public/tfjs_model/' folder with your app.`);

  tf.disposeVariables();
}

main().catch(err => {
  console.error('❌ Training failed:', err);
  process.exit(1);
});
