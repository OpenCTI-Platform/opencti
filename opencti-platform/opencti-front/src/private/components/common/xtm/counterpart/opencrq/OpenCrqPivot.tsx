import React from 'react';
import { XtmEmblem } from '../core/XtmEmblem';
import { OPENCRQ_PRODUCT } from '../core/xtmProducts';

interface OpenCrqPivotProps {
  // The OpenCTI object: the server reads its key (hostname, CVE id or STIX id) under the caller's
  // rights; a type OpenCRQ does not hold answers not_supported and nothing is drawn.
  objectId: string | null | undefined;
}

/** The OpenCRQ emblem of a header (Contract v3: icon only, the three states of XtmEmblem). */
const OpenCrqPivot: React.FC<OpenCrqPivotProps> = ({ objectId }) => <XtmEmblem product={OPENCRQ_PRODUCT} objectId={objectId} />;

export default OpenCrqPivot;
