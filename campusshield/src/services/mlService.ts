import * as tf from '@tensorflow/tfjs';
import { extractFeatures, normalizeUrl, pathHeuristics, type UrlFeatures, FEATURE_COUNT } from './features';

export { extractFeatures } from './features';
export type { UrlFeatures } from './features';

export function featuresToTensor(features: UrlFeatures): tf.Tensor2D {
  const vec = Object.values(features) as number[];
  return tf.tensor2d([vec], [1, vec.length]);
}

let model: tf.LayersModel | null = null;

/**
 * Deep model: 128 → BN → LeakyReLU → Drop(0.3) → 64 → BN → LeakyReLU → Drop(0.3) → 32 → BN → LeakyReLU → Drop(0.2) → 3
 * Input: 29 features (see features.ts)
 */
export async function getModel(): Promise<tf.LayersModel> {
  if (model) return model;

  const modelUrl = `${window.location.origin}/tfjs_model/model.json`;
  const loadTimeout = new Promise<null>((_, reject) =>
    setTimeout(() => reject(new Error('timeout')), 8000)
  );

  try {
    const loaded = await Promise.race([
      tf.loadLayersModel(modelUrl),
      loadTimeout,
    ]);
    if (loaded) {
      model = loaded;
      console.log('✅ Pre-trained TF.js URL classifier loaded from', modelUrl);
      return model;
    }
  } catch {
    console.warn('⚠️ Could not load pre-trained model from', modelUrl, '— training on synthetic data as fallback.');
  }

  model = buildDeepModel();
  await trainModelSynthetic(model);
  console.log('✅ TF.js URL classifier (synthetic fallback) ready');
  return model;
}

function buildDeepModel(): tf.LayersModel {
  const input = tf.input({ shape: [FEATURE_COUNT] });

  const x = tf.layers.dense({ units: 128, kernelInitializer: 'glorotUniform' }).apply(input) as tf.SymbolicTensor;
  const b1 = tf.layers.batchNormalization().apply(x) as tf.SymbolicTensor;
  const a1 = tf.layers.leakyReLU({ alpha: 0.1 }).apply(b1) as tf.SymbolicTensor;
  const d1 = tf.layers.dropout({ rate: 0.3 }).apply(a1) as tf.SymbolicTensor;

  const y = tf.layers.dense({ units: 64, kernelInitializer: 'glorotUniform' }).apply(d1) as tf.SymbolicTensor;
  const b2 = tf.layers.batchNormalization().apply(y) as tf.SymbolicTensor;
  const a2 = tf.layers.leakyReLU({ alpha: 0.1 }).apply(b2) as tf.SymbolicTensor;
  const d2 = tf.layers.dropout({ rate: 0.3 }).apply(a2) as tf.SymbolicTensor;

  const z = tf.layers.dense({ units: 32, kernelInitializer: 'glorotUniform' }).apply(d2) as tf.SymbolicTensor;
  const b3 = tf.layers.batchNormalization().apply(z) as tf.SymbolicTensor;
  const a3 = tf.layers.leakyReLU({ alpha: 0.1 }).apply(b3) as tf.SymbolicTensor;
  const d3 = tf.layers.dropout({ rate: 0.2 }).apply(a3) as tf.SymbolicTensor;

  const output = tf.layers.dense({ units: 3, activation: 'softmax' }).apply(d3) as tf.SymbolicTensor;

  const m = tf.model({ inputs: input, outputs: output });
  m.compile({
    optimizer: tf.train.adam(0.001),
    loss: 'categoricalCrossentropy',
    metrics: ['accuracy'],
  });
  return m;
}

// ─── Synthetic fallback ────────────────────────────────────────────────────────

function syntheticLabel(f: UrlFeatures): [number, number, number] {
  // Strong UNSAFE signals
  if (f.isIp === 1)            return [0, 0, 1];
  if (f.cyrillicChars === 1)   return [0, 0, 1];
  if (f.brandSpoof === 1)      return [0, 0, 1];
  if (f.atSymbol === 1)        return [0, 0, 1];
  if (f.lastSegmentGibberish === 1) return [0, 0, 1];
  if (f.isShortener === 1)     return [0, 0, 1];

  if (f.isTrusted === 1)       return [1, 0, 0];

  const riskScore =
    f.suspiciousTld           * 0.20 +
    f.dotCount                * 0.08 +
    f.pathSuspiciousKwCount   * 0.15 +
    (1 - f.isHttps)           * 0.05 +
    f.hasPort                 * 0.05 +
    f.maxPathSegmentEntropy   * 0.15 +
    f.tldInPath               * 0.10 +
    f.doubleSlashInPath       * 0.08 +
    f.repeatedCharsInPath     * 0.05 +
    f.domainPathRatio         * 0.05 +
    f.queryParamCount         * 0.05 +
    f.pathSpecialCharRatio    * 0.03;

  if (riskScore >= 0.45) return [0, 0, 1];
  if (riskScore >= 0.20) return [0, 1, 0];
  return [1, 0, 0];
}



function randomBetween(a: number, b: number) {
  return a + Math.random() * (b - a);
}

function generateSyntheticSamples(n: number): { xs: number[][]; ys: number[][] } {
  const xs: number[][] = [];
  const ys: number[][] = [];

  for (let i = 0; i < n; i++) {
    const isTrusted = Math.random() < 0.15 ? 1 : 0;
    const isIp      = !isTrusted && Math.random() < 0.03 ? 1 : 0;
    const spoof     = !isTrusted && !isIp && Math.random() < 0.06 ? 1 : 0;
    const highEntropyPath = !isTrusted && !isIp && !spoof && Math.random() < 0.15 ? 1 : 0;
    const hasTldPath = !isTrusted && Math.random() < 0.05 ? 1 : 0;

    const f: UrlFeatures = {
      urlLength:         randomBetween(0.05, isTrusted ? 0.3 : 0.9),
      domainLength:      randomBetween(0.05, isTrusted ? 0.3 : 0.8),
      isHttps:           isTrusted ? 1 : (Math.random() < 0.6 ? 1 : 0),
      atSymbol:          Math.random() < 0.02 ? 1 : 0,
      isIp,
      suspiciousTld:     !isTrusted && Math.random() < 0.12 ? 1 : 0,
      isShortener:       !isTrusted && Math.random() < 0.08 ? 1 : 0,
      hasPort:           Math.random() < 0.04 ? 1 : 0,
      subdomainDepth:    randomBetween(0, isTrusted ? 0.2 : 0.6),
      dotCount:          randomBetween(0, isTrusted ? 0.25 : 0.7),
      dashCount:         randomBetween(0, 0.4),
      numericRatio:      randomBetween(0, isTrusted ? 0.2 : 0.4),
      encodedChars:      !isTrusted && Math.random() < 0.08 ? 1 : 0,
      cyrillicChars:     !isTrusted && Math.random() < 0.03 ? 1 : 0,
      brandSpoof:        spoof ? 1 : 0,
      isTrusted,

      // Path features
      pathLength:              randomBetween(0, isTrusted ? 0.3 : 0.8),
      pathSegmentCount:        randomBetween(0, isTrusted ? 0.25 : 0.75),
      maxPathSegmentEntropy:   highEntropyPath ? randomBetween(0.6, 1) : randomBetween(0, 0.4),
      meanPathSegmentEntropy:  highEntropyPath ? randomBetween(0.4, 0.8) : randomBetween(0, 0.3),
      pathNumericRatio:        randomBetween(0, 0.4),
      pathSpecialCharRatio:    randomBetween(0, highEntropyPath ? 0.4 : 0.15),
      pathSuspiciousKwCount:   !isTrusted ? randomBetween(0, 0.6) : 0,
      lastSegmentGibberish:    highEntropyPath ? 1 : 0,
      tldInPath:               hasTldPath ? 1 : 0,
      queryParamCount:         randomBetween(0, isTrusted ? 0.15 : 0.5),
      doubleSlashInPath:       !isTrusted && Math.random() < 0.05 ? 1 : 0,
      repeatedCharsInPath:     !isTrusted && Math.random() < 0.04 ? 1 : 0,
      domainPathRatio:         randomBetween(0, isTrusted ? 0.3 : 0.8),
    };

    xs.push(Object.values(f) as number[]);
    ys.push(syntheticLabel(f));
  }
  return { xs, ys };
}

async function trainModelSynthetic(m: tf.LayersModel): Promise<void> {
  console.log('⏳ Training synthetic fallback model (1000 samples, 10 epochs)...');
  const start = performance.now();
  const { xs, ys } = generateSyntheticSamples(1000);
  const xTensor = tf.tensor2d(xs);
  const yTensor = tf.tensor2d(ys);

  await m.fit(xTensor, yTensor, {
    epochs: 10,
    batchSize: 32,
    validationSplit: 0.15,
    shuffle: true,
    verbose: 0,
  });

  xTensor.dispose();
  yTensor.dispose();
  console.log(`✅ Synthetic model trained in ${((performance.now() - start) / 1000).toFixed(1)}s`);
}

// ─── Inference ─────────────────────────────────────────────────────────────────

export interface MLResult {
  label: 'SAFE' | 'SUSPICIOUS' | 'UNSAFE';
  confidence: number;
  isHighConfidence: boolean;
}

const CONFIDENCE_THRESHOLD = 0.80;

export async function classifyUrl(url: string): Promise<MLResult> {
  const m = await getModel();
  const features = extractFeatures(url);
  const input    = featuresToTensor(features);

  const output = m.predict(input) as tf.Tensor;
  const probs  = await output.data() as Float32Array;

  input.dispose();
  output.dispose();

  const labels = ['SAFE', 'SUSPICIOUS', 'UNSAFE'] as const;
  const maxIdx = probs.indexOf(Math.max(...probs));

  // Post-ML heuristic override: if path analysis disagrees with ML, prefer heuristics
  try {
    const u = new URL(normalizeUrl(url));
    const heuristic = pathHeuristics(u);
    if (heuristic.isMalicious) {
      return { label: 'UNSAFE', confidence: 0.95, isHighConfidence: true };
    }
    if (heuristic.isSuspicious && labels[maxIdx] === 'SAFE') {
      return { label: 'SUSPICIOUS', confidence: probs[maxIdx], isHighConfidence: false };
    }
  } catch { /* skip heuristic override on parse failure */ }

  return {
    label:            labels[maxIdx],
    confidence:       probs[maxIdx],
    isHighConfidence: probs[maxIdx] >= CONFIDENCE_THRESHOLD,
  };
}
