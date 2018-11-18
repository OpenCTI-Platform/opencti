export const truncate = (str, limit) => {
  if (str === undefined || str === null || str.length <= limit) {
    return str
  } else {
    return str.substring(0, limit) + '...'
  }
}