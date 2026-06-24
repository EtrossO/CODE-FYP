import * as fs from 'node:fs';

const data = fs.readFileSync('malicious_phish.csv', 'utf-8');
const lines = data.trim().split('\n');
const header = lines[0];

const out = ['url,label'];
for (let i = 1; i < lines.length; i++) {
  // Find last comma to split url,type since URLs can contain commas
  const idx = lines[i].lastIndexOf(',');
  const url = lines[i].slice(0, idx);
  const type = lines[i].slice(idx + 1).trim().toLowerCase();
  
  // Map to our 3-class system
  let label;
  if (type === 'benign') label = 'safe';
  else if (type === 'phishing') label = 'unsafe';
  else if (type === 'malware' || type === 'defacement') label = 'suspicious';
  else continue;
  
  out.push(`"${url}",${label}`);
}

fs.writeFileSync('dataset.csv', out.join('\n'));
console.log('dataset.csv created');