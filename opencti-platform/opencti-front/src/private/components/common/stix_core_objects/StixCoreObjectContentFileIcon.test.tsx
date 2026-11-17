import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import StixCoreObjectContentFileIcon from './StixCoreObjectContentFileIcon';

describe('StixCoreObjectContentFileIcon', () => {
  it.each(['image/png', 'image/jpeg'])('shows an image icon for %s', (mimeType) => {
    const { getByTestId } = render(<StixCoreObjectContentFileIcon mimeType={mimeType} />);
    expect(getByTestId('content-file-icon-image')).toBeTruthy();
  });

  it('keeps the PDF icon for PDF files', () => {
    const { getByTestId } = render(<StixCoreObjectContentFileIcon mimeType="application/pdf" />);
    expect(getByTestId('content-file-icon-pdf')).toBeTruthy();
  });
});
