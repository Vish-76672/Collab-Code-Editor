'use strict';

// ShareDB's text OT type does not include cursor transformation by default.
// Presence offsets are UTF-16 positions, the same offsets used by ot-text.
module.exports = function enableTextPresence(type) {
  if (typeof type.transformPresence === 'function') return type;
  type.transformPresence = function (value, op, isOwnOp) {
    if (value === null) return null;
    if (!value || !Number.isSafeInteger(value.anchor) || !Number.isSafeInteger(value.head)) {
      throw new Error('Invalid text presence');
    }
    var range = type.transformSelection([value.anchor, value.head], op, isOwnOp);
    return Object.assign({}, value, {
      anchor: Array.isArray(range) ? range[0] : range,
      head: Array.isArray(range) ? range[1] : range,
    });
  };
  return type;
};
