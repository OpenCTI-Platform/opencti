export const truncate = (str, limit) => {
  if (str === undefined || str === null || str.length <= limit) {
    return str;
  }
  const trimmedStr = str.substr(0, limit);
  return (
    `${trimmedStr.substr(
      0,
      Math.min(trimmedStr.length, trimmedStr.lastIndexOf(' ')),
    )}...`
  );
};
