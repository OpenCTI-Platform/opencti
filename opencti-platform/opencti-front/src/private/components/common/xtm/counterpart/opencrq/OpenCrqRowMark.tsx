import React from 'react';
import { XtmRowMark } from '../core/XtmEmblem';
import { OPENCRQ_PRODUCT } from '../core/xtmProducts';

interface OpenCrqRowMarkProps {
  // The OpenCTI object of the row: the server reads its key under the caller's rights.
  objectId: string | null | undefined;
}

/** The 16 px OpenCRQ mark of a list row, drawn only when OpenCRQ holds the object. */
const OpenCrqRowMark: React.FC<OpenCrqRowMarkProps> = ({ objectId }) => <XtmRowMark product={OPENCRQ_PRODUCT} objectId={objectId} />;

export default OpenCrqRowMark;
