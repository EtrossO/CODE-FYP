/**
 * Campus Shield — TF.js Model Trainer (29-feature)
 *
 * Usage:
 *   node scripts/trainModel.js                              ← synthetic only
 *   node scripts/trainModel.js --data ./dataset.csv --epochs 100
 */

import * as tf from '@tensorflow/tfjs';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

// ═══════════════════════════════════════════════════════════════════════════════
// Feature extraction (mirrors features.ts exactly)
// ═══════════════════════════════════════════════════════════════════════════════

function shannonEntropy(s) {
  const len = s.length;
  if (len < 2) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    h -= p * Math.log2(p);
  }
  return Math.min(h / 4, 1);
}

function isGibberish(segment) {
  if (segment.length < 4) return false;
  const entropy = shannonEntropy(segment);
  if (entropy < 0.6) return false;
  const vowels = (segment.match(/[aeiou]/gi) || []).length;
  const letters = (segment.match(/[a-zA-Z]/g) || []).length;
  if (letters > 0 && (letters - vowels) / letters > 0.8) return true;
  if (segment.length >= 6 && vowels === 0 && letters >= 4) return true;
  return false;
}

function looksLikeBase64(s) {
  if (s.length < 16) return false;
  return /^[A-Za-z0-9+/=_\-]{16,}$/.test(s);
}

function hasRepeatedRun(s, minRun = 4) {
  return /(.)\1{3,}/.test(s);
}

const SUSPICIOUS_TLDS = new Set([
  'tk','ml','ga','cf','gq','xyz','top','work','date','men','loan',
  'download','win','bid','trade','webcam','review','science','party',
  'racing','click','link',
]);

const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'shorturl.at','rb.gy','tiny.cc','cutt.ly','s.id',
]);

const PHISHING_PATH_KW = [
  'login','signin','verify','secure','update','confirm','account',
  'password','credential','banking','paypal','refund','reward','prize',
  'winner','free','urgent','suspended','restrict','unlock','authenticate',
  'token','reset','recovery','authorize','auth','session','2fa','mfa',
  'verification','identity','validate','billing','invoice','payment',
];

const TRUSTED_DOMAINS = new Set([
  'youtube.com','www.youtube.com','m.youtube.com',
  'google.com','goo.gl','www.google.com','mail.google.com','drive.google.com',
  'docs.google.com','maps.google.com','photos.google.com','maps.app.goo.gl',
  'forms.gle','sites.google.com','classroom.google.com','meet.google.com',
  'calendar.google.com','sheets.google.com','slides.google.com','forms.google.com',
  'www.openlearning.com','openlearning.com',
  'www.padlet.com','padlet.com',
  'facebook.com','www.facebook.com','m.facebook.com',
  'twitter.com','www.twitter.com','x.com','www.x.com',
  'instagram.com','www.instagram.com',
  'linkedin.com','www.linkedin.com',
  'whatsapp.com','www.whatsapp.com',
  'amazon.com','www.amazon.com',
  'apple.com','www.apple.com',
  'microsoft.com','www.microsoft.com',
  'github.com','www.github.com',
  'stackoverflow.com','www.stackoverflow.com',
  'wikipedia.org','www.wikipedia.org','en.wikipedia.org',
  'netflix.com','www.netflix.com',
  'spotify.com','www.spotify.com',
  'telegram.org','www.telegram.org',
  'discord.com','www.discord.com',
  'reddit.com','www.reddit.com',
  'zoom.us','www.zoom.us',
  'canva.com','www.canva.com',
  'figma.com','www.figma.com',
  'npmjs.com','www.npmjs.com',
  'react.dev','www.react.dev',
  'uptm.edu.my','www.uptm.edu.my',
  'kptm.edu.my','www.kptm.edu.my',
  'lms.uptm.edu.my','mycms.kptm.edu.my',
  'epay.kptm.edu.my','edupage.org','uptm.edupage.org',
]);

const COMMON_TLDS = new Set([
  'com','org','net','edu','gov','mil','my','uk','jp','de','fr','au',
  'ca','in','br','kr','sg','hk','nz','th','ph','id','vn',
]);

function extractFeatures(url) {
  let u;
  try {
    const s = url.trim();
    const normalized = /^https?:\/\//i.test(s) ? s : s.startsWith('//') ? `https:${s}` : `https://${s}`;
    u = new URL(normalized);
  } catch {
    return {
      urlLength: 1, domainLength: 1, isHttps: 0, atSymbol: 1, isIp: 0,
      suspiciousTld: 1, isShortener: 0, hasPort: 1, subdomainDepth: 0,
      dotCount: 0, dashCount: 0, numericRatio: 0, encodedChars: 1,
      cyrillicChars: 0, brandSpoof: 0, isTrusted: 0,
      pathLength: 1, pathSegmentCount: 1, maxPathSegmentEntropy: 1,
      meanPathSegmentEntropy: 1, pathNumericRatio: 1, pathSpecialCharRatio: 1,
      pathSuspiciousKwCount: 1, lastSegmentGibberish: 1, tldInPath: 1,
      queryParamCount: 1, doubleSlashInPath: 1, repeatedCharsInPath: 1,
      domainPathRatio: 1,
    };
  }

  const hostname = u.hostname.toLowerCase();
  const hostParts = hostname.split('.');
  const tld = hostParts[hostParts.length - 1];
  const regDomain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : hostname;
  const pathname = u.pathname;
  const query = u.search;

  // Domain features
  const brands = ['paypal','facebook','instagram','twitter','linkedin',
    'whatsapp','amazon','apple','microsoft','google','netflix'];
  const hasSpoof = brands.some(b =>
    hostname.includes(b) && !hostname.endsWith('.' + b) && !hostname.startsWith(b + '.')
  );

  // Path features
  const segments = pathname.split('/').filter(Boolean);
  const entropies = segments.map(s => shannonEntropy(s));
  const maxEntropy = entropies.length > 0 ? Math.max(...entropies) : 0;
  const meanEntropy = entropies.length > 0
    ? entropies.reduce((a, b) => a + b, 0) / entropies.length
    : 0;
  const pathDigits = (pathname.match(/\d/g) || []).length;
  const pathNumericRatio = pathname.length > 0 ? pathDigits / pathname.length : 0;
  const specialChars = (pathname.match(/[^a-zA-Z0-9/]/g) || []).length;
  const pathSpecialCharRatio = pathname.length > 0 ? specialChars / pathname.length : 0;
  const hasTldInPath = segments.some(seg => {
    const segLower = seg.toLowerCase();
    return COMMON_TLDS.has(segLower) || [...COMMON_TLDS].some(t => segLower.endsWith('.' + t));
  }) ? 1 : 0;
  const kwInPath = PHISHING_PATH_KW.filter(kw => pathname.toLowerCase().includes(kw)).length;
  const lastSeg = segments[segments.length - 1] || '';
  const lastSegGibberish = lastSeg ? (isGibberish(lastSeg) || looksLikeBase64(lastSeg) ? 1 : 0) : 0;
  const queryParams = query.length > 1 ? query.slice(1).split('&').length : 0;
  const domainPathRatio = hostname.length > 0 ? Math.min(pathname.length / hostname.length, 1) : 0;

  return {
    urlLength: Math.min(url.length / 200, 1),
    domainLength: Math.min(hostname.length / 60, 1),
    isHttps: u.protocol === 'https:' ? 1 : 0,
    atSymbol: url.includes('@') ? 1 : 0,
    isIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
    suspiciousTld: SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    isShortener: SHORTENERS.has(regDomain) ? 1 : 0,
    hasPort: u.port ? 1 : 0,
    subdomainDepth: Math.min(Math.max(hostParts.length - 2, 0) / 4, 1),
    dotCount: Math.min((hostname.match(/\./g) || []).length / 6, 1),
    dashCount: Math.min((hostname.match(/-/g) || []).length / 5, 1),
    numericRatio: (hostname.match(/\d/g) || []).length / Math.max(hostname.length, 1),
    encodedChars: /%[0-9a-fA-F]{2}/.test(hostname) ? 1 : 0,
    cyrillicChars: /[а-яА-Я]/.test(hostname) ? 1 : 0,
    brandSpoof: hasSpoof ? 1 : 0,
    isTrusted: TRUSTED_DOMAINS.has(hostname) ? 1 : 0,

    // Path
    pathLength: Math.min((pathname + query).length / 300, 1),
    pathSegmentCount: Math.min(segments.length / 8, 1),
    maxPathSegmentEntropy: Math.min(maxEntropy, 1),
    meanPathSegmentEntropy: Math.min(meanEntropy, 1),
    pathNumericRatio: pathNumericRatio,
    pathSpecialCharRatio: Math.min(pathSpecialCharRatio / 0.5, 1),
    pathSuspiciousKwCount: Math.min(kwInPath / 4, 1),
    lastSegmentGibberish: lastSegGibberish,
    tldInPath: hasTldInPath,
    queryParamCount: Math.min(queryParams / 8, 1),
    doubleSlashInPath: pathname.includes('//') ? 1 : 0,
    repeatedCharsInPath: segments.some(s => hasRepeatedRun(s)) ? 1 : 0,
    domainPathRatio: domainPathRatio,
  };
}

const FEATURE_COUNT = 29;
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

    // url,label — handle commas in URLs
    const idx = line.lastIndexOf(',');
    const url = line.slice(0, idx)?.trim();
    const label = line.slice(idx + 1)?.trim();
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

function syntheticLabel(f) {
  if (f.isIp === 1)            return [0, 0, 1];
  if (f.cyrillicChars === 1)   return [0, 0, 1];
  if (f.brandSpoof === 1)      return [0, 0, 1];
  if (f.atSymbol === 1)        return [0, 0, 1];
  if (f.lastSegmentGibberish === 1) return [0, 0, 1];
  if (f.isShortener === 1)     return [0, 0, 1];
  if (f.isTrusted === 1)       return [1, 0, 0];

  const risk =
    f.suspiciousTld          * 0.20 +
    f.dotCount               * 0.08 +
    f.pathSuspiciousKwCount  * 0.15 +
    (1 - f.isHttps)          * 0.08 +
    f.hasPort                * 0.05 +
    f.maxPathSegmentEntropy  * 0.15 +
    f.tldInPath              * 0.10 +
    f.doubleSlashInPath      * 0.08 +
    f.repeatedCharsInPath    * 0.05 +
    f.domainPathRatio        * 0.05 +
    f.queryParamCount        * 0.05 +
    f.pathSpecialCharRatio   * 0.03;

  if (risk >= 0.45) return [0, 0, 1];
  if (risk >= 0.20) return [0, 1, 0];
  return [1, 0, 0];
}

function generateSyntheticSamples(n) {
  const xs = [];
  const ys = [];

  for (let i = 0; i < n; i++) {
    const isTrusted = Math.random() < 0.15 ? 1 : 0;
    const isIp = !isTrusted && Math.random() < 0.03 ? 1 : 0;
    const spoof = !isTrusted && !isIp && Math.random() < 0.06 ? 1 : 0;
    const highEntropyPath = !isTrusted && !isIp && !spoof && Math.random() < 0.15 ? 1 : 0;

    const f = {
      urlLength: randomBetween(0.05, isTrusted ? 0.3 : 0.9),
      domainLength: randomBetween(0.05, isTrusted ? 0.3 : 0.8),
      isHttps: isTrusted ? 1 : (Math.random() < 0.6 ? 1 : 0),
      atSymbol: Math.random() < 0.02 ? 1 : 0,
      isIp,
      suspiciousTld: !isTrusted && Math.random() < 0.12 ? 1 : 0,
      isShortener: !isTrusted && Math.random() < 0.08 ? 1 : 0,
      hasPort: Math.random() < 0.04 ? 1 : 0,
      subdomainDepth: randomBetween(0, isTrusted ? 0.2 : 0.6),
      dotCount: randomBetween(0, isTrusted ? 0.25 : 0.7),
      dashCount: randomBetween(0, 0.4),
      numericRatio: randomBetween(0, isTrusted ? 0.2 : 0.4),
      encodedChars: !isTrusted && Math.random() < 0.08 ? 1 : 0,
      cyrillicChars: !isTrusted && Math.random() < 0.03 ? 1 : 0,
      brandSpoof: spoof ? 1 : 0,
      isTrusted,
      pathLength: randomBetween(0, isTrusted ? 0.3 : 0.8),
      pathSegmentCount: randomBetween(0, isTrusted ? 0.25 : 0.75),
      maxPathSegmentEntropy: highEntropyPath ? randomBetween(0.6, 1) : randomBetween(0, 0.4),
      meanPathSegmentEntropy: highEntropyPath ? randomBetween(0.4, 0.8) : randomBetween(0, 0.3),
      pathNumericRatio: randomBetween(0, 0.4),
      pathSpecialCharRatio: randomBetween(0, highEntropyPath ? 0.4 : 0.15),
      pathSuspiciousKwCount: !isTrusted ? randomBetween(0, 0.6) : 0,
      lastSegmentGibberish: highEntropyPath ? 1 : 0,
      tldInPath: !isTrusted && Math.random() < 0.05 ? 1 : 0,
      queryParamCount: randomBetween(0, isTrusted ? 0.15 : 0.5),
      doubleSlashInPath: !isTrusted && Math.random() < 0.05 ? 1 : 0,
      repeatedCharsInPath: !isTrusted && Math.random() < 0.04 ? 1 : 0,
      domainPathRatio: randomBetween(0, isTrusted ? 0.3 : 0.8),
    };

    xs.push(Object.values(f));
    ys.push(syntheticLabel(f));
  }
  return { xs, ys };
}

// ─── Model definition (29-input) ─────────────────────────────────────────────

function buildModel() {
  const input = tf.input({ shape: [FEATURE_COUNT] });

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
  console.log('║        (29-feature deep model)           ║');
  console.log('╚══════════════════════════════════════════╝\n');

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

  const dist = [0, 0, 0];
  for (const y of ys) {
    const idx = y.indexOf(1);
    if (idx >= 0) dist[idx]++;
  }
  console.log(`   Class distribution — SAFE: ${dist[0]}, SUSPICIOUS: ${dist[1]}, UNSAFE: ${dist[2]}`);

  console.log('\n🏗️  Building deep model (128→64→32→3 x 29 features)...');
  const model = buildModel();
  model.summary();

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

  const finalLoss = history.history.loss.at(-1).toFixed(4);
  const finalAcc = (history.history.acc.at(-1) * 100).toFixed(2);
  const valLoss = history.history.val_loss.at(-1).toFixed(4);
  const valAcc = (history.history.val_acc.at(-1) * 100).toFixed(2);

  console.log(`\n📊 Results:`);
  console.log(`   Train Loss: ${finalLoss} | Train Acc: ${finalAcc}%`);
  console.log(`   Val Loss:   ${valLoss} | Val Acc:   ${valAcc}%`);

  // Save using TF.js IO handler (produces format loadLayersModel expects)
  fs.mkdirSync(outputDir, { recursive: true });

  const saveResult = await model.save(tf.io.withSaveHandler(async (artifacts) => {
    const { modelTopology, weightSpecs, weightData } = artifacts;

    // Write weight shard
    const shardBuffer = Buffer.from(weightData);
    fs.writeFileSync(path.join(outputDir, 'group1-shard1of1.bin'), shardBuffer);

    // Build weight manifest with offsets
    let byteOffset = 0;
    const manifestWeights = weightSpecs.map(spec => {
      const w = {
        name: spec.name,
        shape: spec.shape,
        dtype: spec.dtype,
        offset: byteOffset,
        size: spec.shape.reduce((a, b) => a * b, 1) * 4, // float32 = 4 bytes
      };
      byteOffset += w.size;
      return w;
    });

    // Write model.json
    fs.writeFileSync(path.join(outputDir, 'model.json'), JSON.stringify({
      modelTopology,
      weightsManifest: [{
        paths: ['group1-shard1of1.bin'],
        weights: manifestWeights,
      }],
    }, null, 2));

    return { modelArtifactsInfo: { dateSaved: new Date(), modelTopologyType: 'JSON', modelTopologyBytes: 0, weightSpecsBytes: 0, weightDataBytes: 0 } };
  }));

  // Note: saved via IO handler above. The model.json and weight files are
  // already written inside the handler callback.

  console.log(`\n💾 Model saved to: ${outputDir}/`);
  console.log(`   ├─ model.json`);
  console.log(`   └─ group1-shard1of1.bin`);
  console.log(`\n✅ Done!`);

  tf.disposeVariables();
}

main().catch(err => {
  console.error('❌ Training failed:', err);
  process.exit(1);
});
