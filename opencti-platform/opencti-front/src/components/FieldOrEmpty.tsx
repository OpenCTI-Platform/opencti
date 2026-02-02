import React from 'react';
import { isNotEmptyField } from '../utils/utils';
import { EMPTY_VALUE } from '../utils/String';

interface FieldOrEmptyProps<T> {
  source: T;
  children: React.ReactNode;
}

const FieldOrEmpty = <T = unknown>({ source, children }: FieldOrEmptyProps<T>) => {
  return <>{isNotEmptyField(source) ? children : EMPTY_VALUE}</>; // render the children if source is defined
};
export default FieldOrEmpty;
