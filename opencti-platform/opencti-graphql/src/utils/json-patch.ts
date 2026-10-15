import { escapePathComponent, type Operation } from 'fast-json-patch';

type JsonObject = Record<string, unknown>;
type CommonRun = { from: number; to: number; length: number };

export const MAX_ARRAY_EDIT_DISTANCE = 1000;

const isJsonObject = (value: unknown): value is JsonObject => typeof value === 'object' && value !== null && !Array.isArray(value);

const hasDefined = (value: JsonObject, key: string) => Object.hasOwn(value, key) && value[key] !== undefined;

const cloneValue = (value: unknown) => (typeof value === 'object' && value !== null ? JSON.parse(JSON.stringify(value)) : value);

const isInsertion = (frontier: Int32Array, offset: number, diagonal: number, distance: number) => {
  return diagonal === -distance || (diagonal !== distance && frontier[offset + diagonal - 1] < frontier[offset + diagonal + 1]);
};

const backtrackCommonRuns = (history: Int32Array[], fromLength: number, toLength: number): CommonRun[] => {
  const runs: CommonRun[] = [];
  let x = fromLength;
  let y = toLength;
  for (let distance = history.length - 1; distance >= 0; distance -= 1) {
    const frontier = history[distance];
    const offset = distance + 1;
    const diagonal = x - y;
    let startX = 0;
    let previousX = 0;
    let previousY = 0;
    if (distance > 0) {
      const insertion = isInsertion(frontier, offset, diagonal, distance);
      const previousDiagonal = insertion ? diagonal + 1 : diagonal - 1;
      previousX = frontier[offset + previousDiagonal];
      previousY = previousX - previousDiagonal;
      startX = insertion ? previousX : previousX + 1;
    }
    const length = x - startX;
    if (length > 0) {
      runs.push({ from: startX, to: y - length, length });
    }
    x = previousX;
    y = previousY;
  }
  return runs.reverse();
};

const findCommonRuns = (from: unknown[], to: unknown[], maxDistance: number): CommonRun[] | undefined => {
  const offset = maxDistance + 1;
  const frontier = new Int32Array(2 * maxDistance + 3);
  const history: Int32Array[] = [];
  for (let distance = 0; distance <= maxDistance; distance += 1) {
    history.push(frontier.slice(offset - distance - 1, offset + distance + 2));
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      let x = isInsertion(frontier, offset, diagonal, distance) ? frontier[offset + diagonal + 1] : frontier[offset + diagonal - 1] + 1;
      let y = x - diagonal;
      while (x < from.length && y < to.length && from[x] === to[y]) {
        x += 1;
        y += 1;
      }
      frontier[offset + diagonal] = x;
      if (x >= from.length && y >= to.length) {
        return backtrackCommonRuns(history, from.length, to.length);
      }
    }
  }
  return undefined;
};

const elementKey = (value: unknown) => (typeof value === 'object' && value !== null ? JSON.stringify(value) : value);

const diffArray = (from: unknown[], to: unknown[], path: string, operations: Operation[]) => {
  const runs = findCommonRuns(from.map(elementKey), to.map(elementKey), Math.min(to.length, MAX_ARRAY_EDIT_DISTANCE));
  if (!runs) {
    operations.push({ op: 'replace', path, value: cloneValue(to) });
    return;
  }
  let fromIndex = 0;
  let toIndex = 0;
  for (const run of [...runs, { from: from.length, to: to.length, length: 0 }]) {
    const removed = run.from - fromIndex;
    const added = run.to - toIndex;
    const paired = Math.min(removed, added);
    for (let index = 0; index < paired; index += 1) {
      diffValue(from[fromIndex + index], to[toIndex + index], `${path}/${toIndex + index}`, operations);
    }
    for (let index = paired; index < removed; index += 1) {
      operations.push({ op: 'remove', path: `${path}/${toIndex + paired}` });
    }
    for (let index = paired; index < added; index += 1) {
      operations.push({ op: 'add', path: `${path}/${toIndex + index}`, value: cloneValue(to[toIndex + index]) });
    }
    fromIndex = run.from + run.length;
    toIndex = run.to + run.length;
  }
};

const diffObject = (from: JsonObject, to: JsonObject, path: string, operations: Operation[]) => {
  for (const key of Object.keys(from)) {
    if (from[key] === undefined) {
      continue;
    }
    const keyPath = `${path}/${escapePathComponent(key)}`;
    if (hasDefined(to, key)) {
      diffValue(from[key], to[key], keyPath, operations);
    } else {
      operations.push({ op: 'remove', path: keyPath });
    }
  }
  for (const key of Object.keys(to)) {
    if (to[key] !== undefined && !hasDefined(from, key)) {
      operations.push({ op: 'add', path: `${path}/${escapePathComponent(key)}`, value: cloneValue(to[key]) });
    }
  }
};

const diffValue = (from: unknown, to: unknown, path: string, operations: Operation[]) => {
  if (from === to) {
    return;
  }
  if (Array.isArray(from) && Array.isArray(to)) {
    diffArray(from, to, path, operations);
  } else if (isJsonObject(from) && isJsonObject(to)) {
    diffObject(from, to, path, operations);
  } else {
    operations.push({ op: 'replace', path, value: cloneValue(to) });
  }
};

export const computeJsonPatch = (from: unknown, to: unknown): Operation[] => {
  const operations: Operation[] = [];
  diffValue(from, to, '', operations);
  return operations;
};
