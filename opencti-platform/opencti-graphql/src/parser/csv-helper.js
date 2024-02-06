import { UnsupportedError } from '../config/errors';
export const columnNameToIdx = (columnName) => {
    const split = columnName.split('');
    if (split.length === 0
        || split.some((char) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.indexOf(char) === -1)) {
        return -1;
    }
    return split
        .reverse()
        .map((s, i) => {
        const indexOf = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.indexOf(s);
        if (i > 0) {
            return (indexOf + 1) * Math.pow(26, i);
        }
        return indexOf;
    })
        .reduce((acc, v) => acc + v, 0);
};
export const extractValueFromCsv = (record, columnName) => {
    const idx = columnNameToIdx(columnName); // Handle letter to idx here & remove headers
    if (idx < 0) {
        throw UnsupportedError('Unknown column name', { name: columnName });
    }
    else {
        return record[idx];
    }
};
