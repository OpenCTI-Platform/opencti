const parseCalVer = (value: string | null | undefined) => {
  if (!value) return null;
  const normalized = value.trim();
  if (!/^\d+(\.\d+)*$/.test(normalized)) {
    return null;
  }
  return normalized.split('.').map((segment) => Number(segment));
};

export const compareCalVer = (left: string | null | undefined, right: string | null | undefined) => {
  const leftParts = parseCalVer(left);
  const rightParts = parseCalVer(right);

  if (!leftParts || !rightParts) {
    return null;
  }

  const maxLength = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < maxLength; index += 1) {
    const leftValue = leftParts[index] ?? 0;
    const rightValue = rightParts[index] ?? 0;
    if (leftValue > rightValue) return 1;
    if (leftValue < rightValue) return -1;
  }

  return 0;
};
