import { isNotEmptyField } from '../database/utils';

export const filterEmpty = <T>(data: T | null | undefined): data is T => {
  return isNotEmptyField(data);
};
