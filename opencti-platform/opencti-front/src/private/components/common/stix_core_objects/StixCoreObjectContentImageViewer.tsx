import React, { FunctionComponent } from 'react';
import { APP_BASE_PATH } from '../../../../relay/environment';

interface StixCoreObjectContentImageViewerProps {
  fileId: string;
  fileName: string;
  // Height of the panel: at zoom 1 the image is as tall as the panel
  height: number;
  zoom: number;
}

// Read-only preview of a PNG or JPEG file, loaded through the protected storage endpoint
// so access rights, markings and the draft context are enforced by the back end.
const StixCoreObjectContentImageViewer: FunctionComponent<StixCoreObjectContentImageViewerProps> = ({
  fileId,
  fileName,
  height,
  zoom,
}) => (
  <img
    src={`${APP_BASE_PATH}/storage/view/${encodeURIComponent(fileId)}`}
    alt={fileName}
    style={{ height: height * zoom, width: 'auto', maxWidth: 'none' }}
  />
);

export default StixCoreObjectContentImageViewer;
