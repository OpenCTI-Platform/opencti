import React from 'react';
import { XtmEmblem } from '../core/XtmEmblem';
import { OPENAEV_PRODUCT } from '../core/xtmProducts';

interface OpenAevPivotProps {
  // The OpenCTI object: the server reads its key (hostname, MITRE id, CVE id or STIX id) under the caller's rights.
  objectId: string | null | undefined;
}

/** The OpenAEV emblem of a header (Contract v3: icon only, the three states of XtmEmblem). */
const OpenAevPivot: React.FC<OpenAevPivotProps> = ({ objectId }) => <XtmEmblem product={OPENAEV_PRODUCT} objectId={objectId} />;

export default OpenAevPivot;
