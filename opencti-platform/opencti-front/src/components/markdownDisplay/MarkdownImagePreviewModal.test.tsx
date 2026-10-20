import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import MarkdownImagePreviewModal from './MarkdownImagePreviewModal';

const images = [{ src: 'https://example.com/diagram.png', alt: 'Kill chain diagram' }];

describe('MarkdownImagePreviewModal', () => {
  it('stays open when the image or its caption is clicked', async () => {
    const onClose = vi.fn();
    const { user } = testRender(<MarkdownImagePreviewModal open images={images} initialIndex={0} onClose={onClose} />);

    await user.click(screen.getByRole('img', { name: 'Kill chain diagram' }));
    await user.click(screen.getByText('Kill chain diagram'));
    expect(onClose).not.toHaveBeenCalled();
  });

  it('closes when the dark area around the image is clicked', async () => {
    const onClose = vi.fn();
    const { user } = testRender(<MarkdownImagePreviewModal open images={images} initialIndex={0} onClose={onClose} />);

    const slide = screen.getByRole('img', { name: 'Kill chain diagram' }).parentElement as HTMLElement;
    await user.click(slide);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
