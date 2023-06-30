import React, { FunctionComponent } from 'react';
import { isNotEmptyField } from '../utils/utils';

interface FieldOrEmptyProps {
  // Had to use 'any' to allow the component to accept arrays of any type as a source
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  source: string | null | ReadonlyArray<any>;
  children: React.ReactNode;
}

const FieldOrEmpty: FunctionComponent<FieldOrEmptyProps> = ({ source, children }) => {
  return <>{isNotEmptyField(source) ? children : '-'}</>; // render the children if source is defined
};
export default FieldOrEmpty;
