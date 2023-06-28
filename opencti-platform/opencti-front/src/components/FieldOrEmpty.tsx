import React, { FunctionComponent } from 'react';
import { isNotEmptyField } from '../utils/utils';

interface FieldOrEmptyProps {
  source: string | null | ReadonlyArray<any>;
  children: React.ReactNode;
}

const FieldOrEmpty: FunctionComponent<FieldOrEmptyProps> = ({ source, children }) => {
  const notEmptyField = isNotEmptyField(source);
  return <>{notEmptyField ? children : '-'}</>; // render the children if source is defined
};
export default FieldOrEmpty;
