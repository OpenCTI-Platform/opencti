/* eslint-disable @typescript-eslint/no-explicit-any */
// Had to use any to allow the component to accept arrays of any type as source
import React, { FunctionComponent } from 'react';
import { isNotEmptyField } from '../utils/utils';

interface FieldOrEmptyProps {
  source: string | null | ReadonlyArray<any>;
  children: React.ReactNode;
}

const FieldOrEmpty: FunctionComponent<FieldOrEmptyProps> = ({ source, children }) => {
  return <>{isNotEmptyField(source) ? children : '-'}</>; // render the children if source is defined
};
export default FieldOrEmpty;
