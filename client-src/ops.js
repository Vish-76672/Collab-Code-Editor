// client-src/ops.js -- pure translation between editor changes and ot-text ops.
// Kept free of CodeMirror/ShareDB imports so it can be unit-tested in plain Node.

// changes: array of { fromA, toA, text } in ORIGINAL-document coordinates,
// sorted ascending and non-overlapping (this is what CodeMirror's
// iterChanges yields). Returns ONE ot-text op covering all of them.
//
// Why one op: the old code submitted one op per change, but every change's
// position is measured against the ORIGINAL document. After the first op is
// applied, the document has shifted and later positions are wrong. A single
// op that walks the document left to right has no such problem.
function buildOp(changes, oldLength) {
  var op = [];
  var pos = 0;
  changes.forEach(function (c) {
    if (c.fromA > pos) op.push(c.fromA - pos);          // retain untouched text
    if (c.toA > c.fromA) op.push({ d: c.toA - c.fromA }); // delete
    if (c.text.length > 0) op.push(c.text);               // insert
    pos = c.toA;
  });
  if (oldLength > pos) op.push(oldLength - pos);          // retain the tail
  return op;
}

// ot-text op -> list of { from, to, insert } in ORIGINAL coordinates
// (CodeMirror applies a changes array against the document as it was
// before the dispatch, which matches this).
function opToChanges(op) {
  var pos = 0;
  var changes = [];
  op.forEach(function (c) {
    if (typeof c === 'number') pos += c;
    else if (typeof c === 'string') changes.push({ from: pos, to: pos, insert: c });
    else if (c && typeof c.d === 'number') {
      changes.push({ from: pos, to: pos + c.d, insert: '' });
      pos += c.d;
    }
  });
  return changes;
}

module.exports = { buildOp: buildOp, opToChanges: opToChanges };
