import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { DeleteOutlined } from '@mui/icons-material';
import testRender from '../../../utils/tests/test-render';
import IconButton from './IconButton';

describe('IconButton', () => {
  it('should show the tooltip on hover', async () => {
    const { user } = testRender(
      <IconButton
        aria-label="Delete"
        tooltip="Delete this work"
      >
        <DeleteOutlined />
      </IconButton>,
    );

    await user.hover(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Delete this work');
  });

  it('should show the tooltip of a disabled button', async () => {
    const { user } = testRender(
      <IconButton
        aria-label="Delete"
        tooltip="Delete this work"
        disabled
      >
        <DeleteOutlined />
      </IconButton>,
    );

    await user.hover(screen.getByRole('button', { name: 'Delete' }).parentElement as HTMLElement);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Delete this work');
  });

  it('should name the button after a string tooltip when it has no label', () => {
    testRender(
      <IconButton tooltip="Delete this work">
        <DeleteOutlined />
      </IconButton>,
    );

    expect(screen.getByRole('button', { name: 'Delete this work' })).toBeInTheDocument();
  });

  it('should render no tooltip without the prop', async () => {
    const { user } = testRender(
      <IconButton aria-label="Delete">
        <DeleteOutlined />
      </IconButton>,
    );

    await user.hover(screen.getByRole('button', { name: 'Delete' }));
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
  });
});
