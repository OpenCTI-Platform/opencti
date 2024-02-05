import { FunctionalError } from '../config/errors';

export const cropNumber = (value: number, min: number, max: number) => {
  if (!Number.isFinite(value) || !Number.isFinite(min) || !Number.isFinite(max)) {
    throw FunctionalError('Cannot process non-finite input');
  }
  if (min > max) {
    throw FunctionalError('min cannot be greater than max');
  }

  return Math.max(Math.min(value, max), min);
};
