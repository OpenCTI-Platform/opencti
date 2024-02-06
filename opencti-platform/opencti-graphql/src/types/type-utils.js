import { isNotEmptyField } from '../database/utils';
export const filterEmpty = (data) => {
    return isNotEmptyField(data);
};
