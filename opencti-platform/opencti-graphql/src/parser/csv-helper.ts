export const columnNameToIdx = (columnName: string) => {
  const split = columnName.split('');
  return split
    .reverse()
    .map((s, i) => {
      const indexOf = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.indexOf(s);
      if (i > 0) {
        return (indexOf + 1) * 26 ** i;
      }
      return indexOf;
    })
    .reduce((acc, v) => acc + v, 0);
};
