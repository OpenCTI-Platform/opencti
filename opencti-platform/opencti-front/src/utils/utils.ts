import * as R from 'ramda';
import { MESSAGING$ } from '../relay/environment';

export const isNotEmptyField = <T>(field: T | null | undefined): field is T => !R.isEmpty(field) && !R.isNil(field);
export const isEmptyField = <T>(field: T | null | undefined): field is null | undefined => !isNotEmptyField(field);

export const copyToClipboard = (t: (text: string) => string, text: string) => {
  navigator.clipboard.writeText(text);
  MESSAGING$.notifySuccess(t('Copied to clipboard'));
};
