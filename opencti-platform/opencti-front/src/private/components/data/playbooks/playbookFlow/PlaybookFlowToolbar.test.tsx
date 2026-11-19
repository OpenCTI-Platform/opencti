import React, { createRef } from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { ReactFlowProvider } from 'reactflow';
import testRender from '../../../../../utils/tests/test-render';
import PlaybookFlowToolbar from './PlaybookFlowToolbar';

const renderToolbar = () => testRender(
  <ReactFlowProvider>
    <PlaybookFlowToolbar
      direction="vertical"
      onDirectionChange={() => {}}
      canvasRef={createRef<HTMLDivElement>()}
    />
  </ReactFlowProvider>,
);

describe('PlaybookFlowToolbar', () => {
  // The toolbar floats on the canvas: the layout switch is the design system's isolated run (outline, no
  // fill, hover = --bg-input-hover), never the integrated one, whose layer-3 hover is darker than its
  // layer-2 rest in dark mode and reads as a fade next to the icon buttons that light up.
  it('draws the layout switch as an isolated run that lightens on hover', () => {
    renderToolbar();
    const vertical = screen.getByRole('radio', { name: 'Vertical layout' });
    expect(vertical.className).toContain('hover:bg-input-hover');
    expect(vertical.className).not.toContain('hover:bg-[var(--bg-elevation-hover-layer-3)]');
  });

  it('keeps the zoom and fit controls on the tertiary icon button, whose hover is a brand wash', () => {
    renderToolbar();
    ['Zoom out', 'Zoom in', 'Fit view'].forEach((name) => {
      const button = screen.getByRole('button', { name });
      expect(button.className).toContain('hover:bg-filigran-brand-primary-transparency-10');
    });
  });
});
