import React, { FunctionComponent } from 'react';
import { FileImageOutline, FileOutline, FilePdfBox, LanguageHtml5, LanguageMarkdownOutline, NoteTextOutline } from 'mdi-material-ui';
import { isContentTabImage } from './StixCoreObjectContentFileUtils';

interface StixCoreObjectContentFileIconProps {
  mimeType: string;
}

// Icon identifying the type of a file in the Files section of the Content tab
const StixCoreObjectContentFileIcon: FunctionComponent<StixCoreObjectContentFileIconProps> = ({ mimeType }) => {
  if (isContentTabImage(mimeType)) return <FileImageOutline data-testid="content-file-icon-image" />;
  switch (mimeType) {
    case 'text/plain':
      return <NoteTextOutline data-testid="content-file-icon-text" />;
    case 'application/pdf':
      return <FilePdfBox data-testid="content-file-icon-pdf" />;
    case 'text/markdown':
      return <LanguageMarkdownOutline data-testid="content-file-icon-markdown" />;
    case 'text/html':
      return <LanguageHtml5 data-testid="content-file-icon-html" />;
    default:
      return <FileOutline data-testid="content-file-icon-file" />;
  }
};

export default StixCoreObjectContentFileIcon;
