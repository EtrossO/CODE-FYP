import * as tf from '@tensorflow/tfjs';

// ─── Feature extraction ───────────────────────────────────────────────────────
// 18 numeric features derived purely from the URL string — no network calls.

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

export interface UrlFeatures {
  urlLength: number;          // 0 long url
  dotCount: number;           // subdomain depth proxy
  dashCount: number;          // hyphens in hostname
  atSymbol: number;           // @ in url = suspicious
  isHttps: number;            // 1 = https
  isIp: number;               // raw IP address
  suspiciousTld: number;      // known bad TLD
  isShortener: number;        // url shortener
  pathLength: number;         // very long path suspicious
  keywordCount: number;       // phishing keywords hit
  numericRatio: number;       // ratio of digits in hostname
  hasPort: number;            // explicit port = unusual
  subdomainDepth: number;     // dots before registered domain
  encodedChars: number;       // % encoding in hostname
  cyrillicChars: number;      // homograph attack indicator
  brandSpoof: number;         // known brand in subdomain
  isTrusted: number;          // hostname in allowlist
  domainLength: number;       // very long domains suspicious
}

export function extractFeatures(url: string): UrlFeatures {
  let u: URL;
  try {
    u = new URL(url.startsWith('//') ? `https:${url}` : url);
  } catch {
    // Unparseable — max-suspicion feature vector
    return {
      urlLength: 1, dotCount: 0, dashCount: 0, atSymbol: 1,
      isHttps: 0, isIp: 0, suspiciousTld: 1, isShortener: 0,
      pathLength: 1, keywordCount: 1, numericRatio: 0, hasPort: 1,
      subdomainDepth: 0, encodedChars: 1, cyrillicChars: 0,
      brandSpoof: 0, isTrusted: 0, domainLength: 1,
    };
  }

  const hostname = u.hostname.toLowerCase();
  const parts    = hostname.split('.');
  const tld      = parts[parts.length - 1];
  const regDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const path     = u.pathname + u.search;

  // Brand spoof: well-known brand appears as a subdomain prefix but isn't the root
  const brands = ['paypal','facebook','instagram','twitter','linkedin',
                  'whatsapp','amazon','apple','microsoft','google','netflix'];
  const hasSpoof = brands.some(b =>
    hostname.includes(b) && !hostname.endsWith('.' + b) && !hostname.startsWith(b + '.')
  );

  // Normalised to [0,1] ranges where useful
  return {
    urlLength:      Math.min(url.length / 200, 1),
    dotCount:       Math.min((hostname.match(/\./g) || []).length / 6, 1),
    dashCount:      Math.min((hostname.match(/-/g) || []).length / 5, 1),
    atSymbol:       url.includes('@') ? 1 : 0,
    isHttps:        u.protocol === 'https:' ? 1 : 0,
    isIp:           /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
    suspiciousTld:  SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    isShortener:    SHORTENERS.has(regDomain) ? 1 : 0,
    pathLength:     Math.min(path.length / 300, 1),
    keywordCount:   Math.min(
      PHISHING_KW.filter(kw => path.toLowerCase().includes(kw) || hostname.includes(kw)).length / 5,
      1
    ),
    numericRatio:   (hostname.match(/\d/g) || []).length / Math.max(hostname.length, 1),
    hasPort:        u.port ? 1 : 0,
    subdomainDepth: Math.min(Math.max(parts.length - 2, 0) / 4, 1),
    encodedChars:   /%[0-9a-fA-F]{2}/.test(hostname) ? 1 : 0,
    cyrillicChars:  /[а-яА-Я]/.test(hostname) ? 1 : 0,
    brandSpoof:     hasSpoof ? 1 : 0,
    isTrusted:      TRUSTED_DOMAINS.has(hostname) ? 1 : 0,
    domainLength:   Math.min(hostname.length / 60, 1),
  };
}

export function featuresToTensor(features: UrlFeatures): tf.Tensor2D {
  const vec = Object.values(features) as number[];
  return tf.tensor2d([vec], [1, vec.length]);
}

// ─── Model ────────────────────────────────────────────────────────────────────

let model: tf.LayersModel | null = null;

/**
 * Build and train a small feed-forward network on synthetic rule-based labels.
 * In production you'd load a pre-trained model with tf.loadLayersModel().
 * Here we generate ~800 training examples from the same heuristics already in
 * geminiService.ts, so the model learns to generalise them.
 */
export async function getModel(): Promise<tf.LayersModel> {
  if (model) return model;

  model = buildModel();
  await trainModel(model);
  console.log('✅ TF.js URL classifier ready');
  return model;
}

function buildModel(): tf.LayersModel {
  const m = tf.sequential();
  m.add(tf.layers.dense({ inputShape: [18], units: 32, activation: 'relu',
    kernelInitializer: 'glorotUniform' }));
  m.add(tf.layers.dropout({ rate: 0.2 }));
  m.add(tf.layers.dense({ units: 16, activation: 'relu' }));
  m.add(tf.layers.dense({ units: 3, activation: 'softmax' })); // [safe, suspicious, unsafe]
  m.compile({ optimizer: tf.train.adam(0.001), loss: 'categoricalCrossentropy',
    metrics: ['accuracy'] });
  return m;
}

// Synthetic dataset generator — labels come from rule-based logic.
// Classes: 0 = SAFE, 1 = SUSPICIOUS, 2 = UNSAFE
function syntheticLabel(f: UrlFeatures): [number, number, number] {
  if (f.isTrusted === 1)       return [1,0,0];
  if (f.isIp === 1)            return [0,0,1];
  if (f.cyrillicChars === 1)   return [0,0,1];
  if (f.brandSpoof === 1)      return [0,0,1];
  if (f.atSymbol === 1)        return [0,0,1];

  const riskScore =
    f.suspiciousTld * 0.25 +
    f.isShortener   * 0.15 +
    f.dotCount      * 0.15 +
    f.keywordCount  * 0.20 +
    f.pathLength    * 0.10 +
    f.encodedChars  * 0.10 +
    (1 - f.isHttps) * 0.15 +
    f.hasPort       * 0.10;

  if (riskScore >= 0.45) return [0,0,1];
  if (riskScore >= 0.20) return [0,1,0];
  return [1,0,0];
}

function randomBetween(a: number, b: number) {
  return a + Math.random() * (b - a);
}

function generateSyntheticSamples(n: number): { xs: number[][]; ys: number[][] } {
  const xs: number[][] = [];
  const ys: number[][] = [];

  for (let i = 0; i < n; i++) {
    const isTrusted = Math.random() < 0.2 ? 1 : 0;
    const isIp      = !isTrusted && Math.random() < 0.05 ? 1 : 0;
    const spoof     = !isTrusted && !isIp && Math.random() < 0.08 ? 1 : 0;

    const f: UrlFeatures = {
      urlLength:      randomBetween(0.05, isTrusted ? 0.3 : 0.9),
      dotCount:       randomBetween(0, isTrusted ? 0.3 : 0.8),
      dashCount:      randomBetween(0, 0.5),
      atSymbol:       Math.random() < 0.03 ? 1 : 0,
      isHttps:        isTrusted ? 1 : (Math.random() < 0.6 ? 1 : 0),
      isIp,
      suspiciousTld:  !isTrusted && Math.random() < 0.15 ? 1 : 0,
      isShortener:    !isTrusted && Math.random() < 0.1  ? 1 : 0,
      pathLength:     randomBetween(0, 0.7),
      keywordCount:   !isTrusted ? randomBetween(0, 0.6) : 0,
      numericRatio:   randomBetween(0, 0.3),
      hasPort:        Math.random() < 0.05 ? 1 : 0,
      subdomainDepth: randomBetween(0, isTrusted ? 0.25 : 0.75),
      encodedChars:   !isTrusted && Math.random() < 0.1  ? 1 : 0,
      cyrillicChars:  !isTrusted && Math.random() < 0.04 ? 1 : 0,
      brandSpoof:     spoof ? 1 : 0,
      isTrusted,
      domainLength:   randomBetween(0, isTrusted ? 0.4 : 0.9),
    };

    xs.push(Object.values(f) as number[]);
    ys.push(syntheticLabel(f));
  }
  return { xs, ys };
}

async function trainModel(m: tf.LayersModel): Promise<void> {
  const { xs, ys } = generateSyntheticSamples(1200);
  const xTensor = tf.tensor2d(xs);
  const yTensor = tf.tensor2d(ys);

  await m.fit(xTensor, yTensor, {
    epochs: 30,
    batchSize: 32,
    validationSplit: 0.15,
    shuffle: true,
    verbose: 0,
  });

  xTensor.dispose();
  yTensor.dispose();
}

// ─── Inference ────────────────────────────────────────────────────────────────

export interface MLResult {
  label: 'SAFE' | 'SUSPICIOUS' | 'UNSAFE';
  confidence: number; // 0–1
  isHighConfidence: boolean;
}

const CONFIDENCE_THRESHOLD = 0.80; // Only act on high-confidence predictions

export async function classifyUrl(url: string): Promise<MLResult> {
  const m = await getModel();
  const features = extractFeatures(url);
  const input    = featuresToTensor(features);

  const output = m.predict(input) as tf.Tensor;
  const probs  = await output.data() as Float32Array; // [safe, suspicious, unsafe]

  input.dispose();
  output.dispose();

  const labels = ['SAFE', 'SUSPICIOUS', 'UNSAFE'] as const;
  const maxIdx = probs.indexOf(Math.max(...probs));

  return {
    label:            labels[maxIdx],
    confidence:       probs[maxIdx],
    isHighConfidence: probs[maxIdx] >= CONFIDENCE_THRESHOLD,
  };
}