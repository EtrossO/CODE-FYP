import * as fs from 'node:fs';

const data = fs.readFileSync('malicious_phish.csv', 'utf-8');
const lines = data.trim().split('\n');

const out = ['url,label'];
for (let i = 1; i < lines.length; i++) {
  const idx = lines[i].lastIndexOf(',');
  const url = lines[i].slice(0, idx);
  const type = lines[i].slice(idx + 1).trim().toLowerCase();

  let label;
  if (type === 'benign') label = 'safe';
  else if (type === 'phishing') label = 'unsafe';
  else if (type === 'malware' || type === 'defacement') label = 'suspicious';
  else continue;

  out.push(`"${url}",${label}`);
}

const outPath = 'dataset.csv';
fs.writeFileSync(outPath, out.join('\n'));
console.log(`✅ ${outPath} created with ${out.length - 1} samples`);
