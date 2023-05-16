import React, { FunctionComponent } from 'react';
import { isNotEmptyField } from '../utils/utils';

interface FieldOrEmptyProps {
  source: string | null | ReadonlyArray<string | null>;
  children: React.ReactNode;
}

const FieldOrEmpty: FunctionComponent<FieldOrEmptyProps> = ({ source, children }) => {
  return <>{isNotEmptyField(source) ? children : '-'}</>; // render the children if source is defined
};
export default FieldOrEmpty;
