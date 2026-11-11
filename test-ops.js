// Randomised round-trip test for the op translation (run: node test-ops.js)
const { buildOp, opToChanges } = require('./client-src/ops');

function applyOp(doc, op) {           // reference ot-text interpreter
  let out = '', pos = 0;
  for (const c of op) {
    if (typeof c === 'number') { out += doc.slice(pos, pos + c); pos += c; }
    else if (typeof c === 'string') out += c;
    else { pos += c.d; }
  }
  if (pos !== doc.length) throw new Error('op does not span document: ' + pos + ' vs ' + doc.length);
  return out;
}
function applyChanges(doc, ch) {      // CodeMirror semantics: all in original coords
  let out = doc;
  [...ch].sort((a, b) => b.from - a.from).forEach(c => { out = out.slice(0, c.from) + c.insert + out.slice(c.to); });
  return out;
}
const rnd = (n) => Math.floor(Math.random() * n);
const word = () => 'abcxyz\n '.repeat(2).split('').sort(() => Math.random() - .5).slice(0, rnd(6)).join('');

let fails = 0;
for (let i = 0; i < 5000; i++) {
  const doc = Array.from({ length: rnd(60) }, () => 'ab\n c'[rnd(5)]).join('');
  const changes = []; let pos = 0;
  while (pos <= doc.length && changes.length < 5 && Math.random() < 0.7) {
    const fromA = pos + rnd(doc.length - pos + 1);
    const toA = fromA + rnd(doc.length - fromA + 1) % 4;
    changes.push({ fromA, toA: Math.min(toA, doc.length), text: word() });
    pos = Math.min(toA, doc.length) + 1;
  }
  let expected = doc;
  [...changes].sort((a, b) => b.fromA - a.fromA).forEach(c => { expected = expected.slice(0, c.fromA) + c.text + expected.slice(c.toA); });
  const op = buildOp(changes, doc.length);
  try {
    if (applyOp(doc, op) !== expected) throw new Error('buildOp mismatch');
    if (applyChanges(doc, opToChanges(op)) !== expected) throw new Error('opToChanges mismatch');
  } catch (e) { fails++; if (fails < 4) console.log('FAIL', e.message, JSON.stringify({ doc, changes, op })); }
}
// the old per-change approach, to prove it really was broken for multi-change edits
let oldBroken = 0;
for (let i = 0; i < 500; i++) {
  const doc = 'line1\nline2\nline3\n';
  const changes = [{ fromA: 0, toA: 0, text: '  ' }, { fromA: 6, toA: 6, text: '  ' }, { fromA: 12, toA: 12, text: '  ' }];
  let cur = doc;
  try {
    changes.forEach(c => { const op = []; if (c.fromA) op.push(c.fromA); op.push(c.text); op.push(cur.length - c.toA); cur = applyOp(cur, op); });
  } catch (e) { oldBroken++; }
  if (cur !== '  line1\n  line2\n  line3\n') oldBroken++;
}
console.log(fails === 0 ? 'PASS: 5000 random multi-change edits round-trip correctly' : 'FAILED ' + fails);
console.log('old per-change method wrong/invalid on indent-3-lines case:', oldBroken > 0 ? 'yes (bug confirmed)' : 'no');
process.exit(fails ? 1 : 0);
