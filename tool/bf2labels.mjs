// Convert a CTU-13 .binetflow into a probe/bench labels.csv (one row per
// IP-pair: "src,dst,Botnet" or "src,dst,BENIGN"). Botnet if any flow for that
// pair is labeled Botnet; Normal/Background -> BENIGN. Pair-keyed (the probe
// matches alerts order-independently by IP pair).
//   node tool/bf2labels.mjs <in.binetflow> <out.csv>
import { createReadStream, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const inPath = process.argv[2], outPath = process.argv[3];
if (!inPath || !outPath) { console.error('usage: bf2labels <in.binetflow> <out.csv>'); process.exit(1); }

const ipNum = (s) => { const p = s.split('.'); return p.length === 4 ? ((+p[0]<<24)>>>0) + (+p[1]<<16) + (+p[2]<<8) + (+p[3]) : 0; };

let cols = null, ci = {};
const pairs = new Map(); // normKey -> {src,dst,bot,tot}
const rl = createInterface({ input: createReadStream(inPath) });
let n = 0;
rl.on('line', (line) => {
  if (!cols) {
    cols = line.split(',');
    cols.forEach((c, i) => { ci[c] = i; });
    return;
  }
  if (!line) return;
  const c = line.split(',');
  const a = c[ci['SrcAddr']], b = c[ci['DstAddr']], label = (c[ci['Label']] || '');
  if (!a || !b) return;
  const an = ipNum(a), bn = ipNum(b);
  const key = an <= bn ? a + '|' + b : b + '|' + a;
  let e = pairs.get(key);
  if (!e) { e = { src: a, dst: b, bot: 0, tot: 0 }; pairs.set(key, e); }
  e.tot++;
  if (/botnet/i.test(label)) e.bot++;
  n++;
});
rl.on('close', () => {
  const out = ['# auto-generated from ' + inPath];
  let bot = 0, ben = 0;
  for (const e of pairs.values()) {
    if (e.bot > 0) { out.push(`${e.src},${e.dst},Botnet`); bot++; }
    else { out.push(`${e.src},${e.dst},BENIGN`); ben++; }
  }
  writeFileSync(outPath, out.join('\n') + '\n');
  console.log(`${inPath}: ${n} flows -> ${pairs.size} pairs (${bot} botnet, ${ben} benign) -> ${outPath}`);
});
