/**
 * Campus Shield — TF.js Model Trainer (33-feature)
 *
 * Feature extraction is imported directly from src/services/features.ts
 * (single source of truth — no drift between training and inference).
 *
 * Usage:
 *   node scripts/trainModel.js                                  ← balanced 9k dataset
 *   node scripts/trainModel.js --data ./dataset.csv --epochs 60 --batchSize 64
 *   node scripts/trainModel.js --data ./malicious_phish.csv --maxSamples 30000
 *
 * Output:
 *   public/tfjs_model/model.json + group1-shard1of1.bin
 *   public/tfjs_model/metrics.json  (confusion matrix, per-class P/R/F1)
 */

import * as tf from '@tensorflow/tfjs';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { extractFeatures, FEATURE_COUNT, FEATURE_NAMES } from '../src/services/features.ts';

const CLASSES = ['SAFE', 'SUSPICIOUS', 'UNSAFE'];

// Maps every label convention (label / type column) to class index.
const LABEL_MAP = {
  safe: 0, benign: 0,
  suspicious: 1, defacement: 1, malware: 1,
  unsafe: 2, phishing: 2,
};

function oneHot(label, numClasses = CLASSES.length) {
  const vec = new Array(numClasses).fill(0);
  const idx = LABEL_MAP[label?.toLowerCase()?.trim()];
  vec[idx ?? 1] = 1; // unknown → SUSPICIOUS
  return vec;
}

/** Strip a wrapping pair of double quotes from a CSV field. */
function unquote(s) {
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s;
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

    // Split at the LAST comma so URLs containing commas survive.
    const idx = line.lastIndexOf(',');
    const rawUrl = line.slice(0, idx)?.trim();
    const rawLabel = line.slice(idx + 1)?.trim()?.toLowerCase();

    const url = unquote(rawUrl);
    const label = unquote(rawLabel);
    if (!url || !label) { skipped++; continue; }
    if (LABEL_MAP[label] === undefined) { skipped++; continue; }
    // Skip rows with control characters (corrupted binary data)
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(url)) { skipped++; continue; }

    let features;
    try {
      features = extractFeatures(url);
    } catch {
      skipped++;
      continue;
    }

    xs.push(Object.values(features));
    ys.push(oneHot(label));

    if (xs.length >= maxSamples) break;
  }

  console.log(`  Loaded ${xs.length} samples${skipped > 0 ? ` (${skipped} skipped)` : ''}`);
  return { xs, ys };
}

// ─── Synthetic fallback (no --data) ───────────────────────────────────────────

function randomBetween(a, b) { return a + Math.random() * (b - a); }

function syntheticLabel(f) {
  if (f.isIp === 1)            return [0, 0, 1];
  if (f.cyrillicChars === 1)   return [0, 0, 1];
  if (f.brandSpoof === 1)      return [0, 0, 1];
  if (f.atSymbol === 1)        return [0, 0, 1];
  if (f.suspiciousScheme === 1)return [0, 0, 1];
  if (f.lastSegmentGibberish === 1) return [0, 0, 1];
  if (f.isShortener === 1)     return [0, 0, 1];
  if (f.isTrusted === 1)       return [1, 0, 0];
  if (f.punycode === 1)        return [0, 1, 0];

  const risk =
    f.suspiciousTld          * 0.20 +
    f.dotCount               * 0.08 +
    f.pathSuspiciousKwCount  * 0.15 +
    (1 - f.isHttps)          * 0.05 +
    f.hasPort                * 0.05 +
    f.maxPathSegmentEntropy  * 0.15 +
    f.tldInPath              * 0.10 +
    f.doubleSlashInPath      * 0.08 +
    f.repeatedCharsInPath    * 0.05 +
    f.domainPathRatio        * 0.05 +
    f.queryParamCount        * 0.05 +
    f.pathSpecialCharRatio   * 0.03 +
    f.queryEntropy           * 0.10 +
    f.brandSubstring         * 0.12;

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
    const hasBrandSub = !isTrusted && Math.random() < 0.08 ? 1 : 0;
    const hasPunycode = !isTrusted && Math.random() < 0.04 ? 1 : 0;

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
      punycode: hasPunycode ? 1 : 0,
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
      queryEntropy: highEntropyPath ? randomBetween(0.5, 1) : randomBetween(0, 0.35),
      brandSubstring: hasBrandSub ? 1 : 0,
      suspiciousScheme: !isTrusted && Math.random() < 0.02 ? 1 : 0,
    };

    xs.push(Object.values(f));
    ys.push(syntheticLabel(f));
  }
  return { xs, ys };
}

// ─── Model definition (33-input) ─────────────────────────────────────────────

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

  const output = tf.layers.dense({ units: CLASSES.length, activation: 'softmax' }).apply(d3);

  const m = tf.model({ inputs: input, outputs: output });
  m.compile({
    optimizer: tf.train.adam(0.001),
    loss: 'categoricalCrossentropy',
    metrics: ['accuracy'],
  });
  return m;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function classDistribution(ys) {
  const dist = new Array(CLASSES.length).fill(0);
  for (const y of ys) dist[y.indexOf(1)]++;
  return dist;
}

/** Inverse-frequency class weights to counter class imbalance. */
function computeClassWeights(ys) {
  const dist = classDistribution(ys);
  const total = ys.length;
  const weights = {};
  for (let i = 0; i < CLASSES.length; i++) {
    weights[i] = dist[i] > 0 ? total / (CLASSES.length * dist[i]) : 1;
  }
  return weights;
}

/** Deterministic (seeded) shuffle that keeps feature/label rows paired. */
function seededShuffle(n, seed = 42) {
  const order = Array.from({ length: n }, (_, i) => i);
  let s = seed;
  const rnd = () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order;
}

/**
 * Evaluate the model on a holdout set.
 * Returns accuracy, per-class precision/recall/F1, macro-F1 and a confusion matrix.
 */
function evaluate(model, xs, ys) {
  const n = ys.length;
  const classes = CLASSES.length;

  const predTensor = model.predict(tf.tensor2d(xs));
  const predData = predTensor.dataSync();
  predTensor.dispose();

  const cm = Array.from({ length: classes }, () => new Array(classes).fill(0));
  for (let i = 0; i < n; i++) {
    let pIdx = 0, best = -1;
    for (let c = 0; c < classes; c++) {
      const v = predData[i * classes + c];
      if (v > best) { best = v; pIdx = c; }
    }
    cm[ys[i].indexOf(1)][pIdx]++;
  }

  const perClass = CLASSES.map((name, i) => {
    const tp = cm[i][i];
    const fp = cm.reduce((a, row, r) => a + (r !== i ? row[i] : 0), 0);
    const fn = cm[i].reduce((a, c) => a + c, 0) - tp;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
    return { class: name, tp, fp, fn, precision, recall, f1 };
  });

  const accuracy = cm.reduce((a, row, r) => a + row[r], 0) / n;
  const macroF1 = perClass.reduce((a, p) => a + p.f1, 0) / classes;

  return { accuracy, macroF1, perClass, confusionMatrix: cm };
}

// ─── Save model + metrics ─────────────────────────────────────────────────────

async function saveModel(model, outputDir, runInfo) {
  fs.mkdirSync(outputDir, { recursive: true });

  const saveResult = await model.save(tf.io.withSaveHandler(async (artifacts) => {
    const { modelTopology, weightSpecs, weightData } = artifacts;

    const shardBuffer = Buffer.from(weightData);
    fs.writeFileSync(path.join(outputDir, 'group1-shard1of1.bin'), shardBuffer);

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

    fs.writeFileSync(path.join(outputDir, 'model.json'), JSON.stringify({
      modelTopology,
      weightsManifest: [{
        paths: ['group1-shard1of1.bin'],
        weights: manifestWeights,
      }],
    }, null, 2));

    return { modelArtifactsInfo: { dateSaved: new Date(), modelTopologyType: 'JSON', modelTopologyBytes: 0, weightSpecsBytes: 0, weightDataBytes: 0 } };
  }));

  // Metrics report (JSON) — useful for FYP documentation / evaluation evidence
  fs.writeFileSync(path.join(outputDir, 'metrics.json'), JSON.stringify(runInfo, null, 2));
  console.log(`📊 metrics written to: ${path.join(outputDir, 'metrics.json')}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args = {};
  const raw = process.argv.slice(2);
  for (let i = 0; i < raw.length; i++) {
    if (raw[i].startsWith('--')) {
      const key = raw[i].slice(2);
      args[key] = raw[i + 1] && !raw[i + 1].startsWith('--') ? raw[i + 1] : true;
      if (args[key] !== true) i++;
    }
  }
  if (!args.data) {
    const defaultPath = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '..', 'dataset_balanced_9k.csv'
    );
    if (fs.existsSync(defaultPath)) {
      args.data = defaultPath;
    }
  }

  const dataPath = args.data;
  const outputDir = args.output || path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..', 'public', 'tfjs_model'
  );
  const epochs = parseInt(args.epochs, 10) || 60;
  const batchSize = parseInt(args.batchSize, 10) || 64;
  const valSplit = parseFloat(args.valSplit) || 0.2;
  const seed = parseInt(args.seed, 10) || 42;

  console.log('╔══════════════════════════════════════════╗');
  console.log('║   Campus Shield — TF.js Model Trainer   ║');
  console.log('║         (33-feature deep model)          ║');
  console.log('╚══════════════════════════════════════════╝\n');

  let xs, ys;
  if (dataPath) {
    const fullPath = path.resolve(dataPath);
    if (!fs.existsSync(fullPath)) {
      console.error(`❌ Dataset not found: ${fullPath}`);
      process.exit(1);
    }
    console.log(`📂 Loading dataset: ${fullPath}`);
    const maxSamples = parseInt(args.maxSamples, 10) || Infinity;
    const data = await loadCSV(fullPath, maxSamples);
    xs = data.xs;
    ys = data.ys;
    if (xs.length === 0) {
      console.error('❌ No valid samples found in CSV');
      process.exit(1);
    }
    console.log(`   Samples: ${xs.length} | Features: ${FEATURE_COUNT}`);
  } else {
    console.log('🧪 No --data provided. Generating synthetic dataset...');
    const syntheticSize = parseInt(args.synthetic, 10) || 5000;
    const data = generateSyntheticSamples(syntheticSize);
    xs = data.xs;
    ys = data.ys;
    console.log(`   Samples: ${xs.length} (synthetic)`);
  }

  console.log(`   Class distribution — ${CLASSES.map((c, i) => `${c}: ${classDistribution(ys)[i]}`).join(', ')}`);

  // Holdout split (stratified by class to keep evaluation fair)
  const order = seededShuffle(xs.length, seed);
  const splitIdx = Math.floor(xs.length * (1 - valSplit));
  const trainIdx = order.slice(0, splitIdx);
  const testIdx = order.slice(splitIdx);

  const pick = (arr, idx) => idx.map(i => arr[i]);
  const trainXs = pick(xs, trainIdx);
  const trainYs = pick(ys, trainIdx);
  const testXs = pick(xs, testIdx);
  const testYs = pick(ys, testIdx);

  console.log(`   Train: ${trainXs.length} | Holdout test: ${testXs.length}`);
  console.log(`   Test distribution — ${CLASSES.map((c, i) => `${c}: ${classDistribution(testYs)[i]}`).join(', ')}`);

  // Class weights handle imbalance (e.g. dataset_50k.csv is 73% SAFE)
  const classWeights = computeClassWeights(trainYs);
  console.log('   Class weights:', JSON.stringify(classWeights));

  console.log(`\n🏗️  Building deep model (128→64→32→3 x ${FEATURE_COUNT} features)...`);
  const model = buildModel();
  model.summary();

  const xTensor = tf.tensor2d(trainXs);
  const yTensor = tf.tensor2d(trainYs);

  console.log(`\n🚀 Training for ${epochs} epochs (batch=${batchSize}, val_split=${valSplit})...\n`);

  const history = await model.fit(xTensor, yTensor, {
    epochs,
    batchSize,
    validationSplit: 0.1,
    shuffle: true,
    verbose: 1,
    classWeight: classWeights,
    callbacks: [
      tf.callbacks.earlyStopping({ monitor: 'val_acc', patience: 8 }),
    ],
  });

  xTensor.dispose();
  yTensor.dispose();

  const finalLoss = history.history.loss.at(-1).toFixed(4);
  const finalAcc = (history.history.acc.at(-1) * 100).toFixed(2);

  console.log(`\n📊 Final training accuracy: ${finalAcc}% (loss ${finalLoss})`);

  // Evaluate on the untouched holdout test set
  console.log('\n🧪 Evaluating on holdout test set...');
  const evalResult = evaluate(model, testXs, testYs);

  console.log(`\n   Test Accuracy: ${(evalResult.accuracy * 100).toFixed(2)}%`);
  console.log(`   Macro F1:      ${(evalResult.macroF1 * 100).toFixed(2)}%`);
  console.log('   ── Confusion Matrix (rows = actual, cols = predicted) ──');
  const header = '   ' + CLASSES.map((c, i) => c.padEnd(12)).join('');
  console.log(header);
  evalResult.confusionMatrix.forEach((row, i) => {
    console.log('   ' + CLASSES[i].padEnd(12) + row.map(v => String(v).padEnd(12)).join(''));
  });
  console.log('   ── Per-class metrics ──');
  for (const p of evalResult.perClass) {
    console.log(`   ${p.class.padEnd(12)} precision=${(p.precision * 100).toFixed(1)}% recall=${(p.recall * 100).toFixed(1)}% F1=${(p.f1 * 100).toFixed(1)}%`);
  }

  const runInfo = {
    generatedAt: new Date().toISOString(),
    featureCount: FEATURE_COUNT,
    featureNames: FEATURE_NAMES,
    classes: CLASSES,
    dataset: dataPath ? path.resolve(dataPath) : 'synthetic',
    samples: xs.length,
    trainSamples: trainXs.length,
    testSamples: testXs.length,
    trainDistribution: classDistribution(trainYs),
    testDistribution: classDistribution(testYs),
    classWeights,
    epochs,
    batchSize,
    finalTrainingAccuracy: parseFloat(finalAcc),
    finalTrainingLoss: parseFloat(finalLoss),
    test: {
      accuracy: evalResult.accuracy,
      macroF1: evalResult.macroF1,
      perClass: evalResult.perClass,
      confusionMatrix: evalResult.confusionMatrix,
    },
  };

  await saveModel(model, outputDir, runInfo);

  console.log(`\n💾 Model saved to: ${outputDir}/`);
  console.log(`   ├─ model.json`);
  console.log(`   ├─ group1-shard1of1.bin`);
  console.log(`   └─ metrics.json`);
  console.log('\n✅ Done!');

  tf.disposeVariables();
}

main().catch(err => {
  console.error('❌ Training failed:', err);
  process.exit(1);
});
