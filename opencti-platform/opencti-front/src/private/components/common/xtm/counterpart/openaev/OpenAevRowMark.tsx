import React from 'react';
import { XtmRowMark } from '../core/XtmEmblem';
import { OPENAEV_PRODUCT } from '../core/xtmProducts';

interface OpenAevRowMarkProps {
  // The OpenCTI object of the row: the server reads its key under the caller's rights.
  objectId: string | null | undefined;
}

/** The 16 px OpenAEV mark of a list row, drawn only when OpenAEV holds the object. */
const OpenAevRowMark: React.FC<OpenAevRowMarkProps> = ({ objectId }) => <XtmRowMark product={OPENAEV_PRODUCT} objectId={objectId} />;

export default OpenAevRowMark;
