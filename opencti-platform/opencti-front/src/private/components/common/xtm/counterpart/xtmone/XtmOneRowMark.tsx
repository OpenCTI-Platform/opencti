import React from 'react';
import { XtmRowMark } from '../core/XtmEmblem';
import { XTMONE_PRODUCT } from '../core/xtmProducts';

interface XtmOneRowMarkProps {
  // The OpenCTI object of the row: the server reads its key under the caller's rights.
  objectId: string | null | undefined;
}

/** The 16 px XTM One mark of a list row, in the XTM One purple, drawn only when the XTM One inventory holds the asset. */
const XtmOneRowMark: React.FC<XtmOneRowMarkProps> = ({ objectId }) => <XtmRowMark product={XTMONE_PRODUCT} objectId={objectId} />;

export default XtmOneRowMark;
