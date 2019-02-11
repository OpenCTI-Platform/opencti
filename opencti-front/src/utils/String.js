export const truncate = (str, limit) => {
  if (str === undefined || str === null || str.length <= limit) {
    return str;
  }
  return `${str.substring(0, limit)}...`;
};
