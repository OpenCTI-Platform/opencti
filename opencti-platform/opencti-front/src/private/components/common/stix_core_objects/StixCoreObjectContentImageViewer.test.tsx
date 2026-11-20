import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import StixCoreObjectContentImageViewer from './StixCoreObjectContentImageViewer';

vi.mock('../../../../relay/environment', () => ({ APP_BASE_PATH: '/base' }));

describe('StixCoreObjectContentImageViewer', () => {
  it('loads the image through the protected storage view endpoint', () => {
    render(<StixCoreObjectContentImageViewer fileId="import/Report/abc/my shot.png" fileName="my shot.png" height={500} zoom={1} />);
    expect(screen.getByRole('img', { name: 'my shot.png' }).getAttribute('src'))
      .toBe('/base/storage/view/import%2FReport%2Fabc%2Fmy%20shot.png');
  });

  it('scales the image height with the zoom, like a PDF page', () => {
    render(<StixCoreObjectContentImageViewer fileId="a.png" fileName="a.png" height={500} zoom={1.4} />);
    expect(screen.getByRole('img', { name: 'a.png' }).style.height).toBe('700px');
  });
});
