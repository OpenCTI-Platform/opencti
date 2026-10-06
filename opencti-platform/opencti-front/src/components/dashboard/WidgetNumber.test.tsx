import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import WidgetNumber from './WidgetNumber';
import testRender from '../../utils/tests/test-render';

describe('WidgetNumber', () => {
  it('renders a plain value when there is no drilldown link', () => {
    testRender(<WidgetNumber label="Malwares" value={42} />);
    const node = screen.getByTestId('card-number-Malwares');
    expect(node.tagName).toBe('DIV');
    expect(node.textContent).toContain('42');
  });

  it('renders a link carrying noDrag when a drilldown link is provided', () => {
    testRender(<WidgetNumber label="Malwares" value={42} drilldownLink="/dashboard/arsenal/malwares?filters=%7B%7D" />);
    const node = screen.getByTestId('card-number-Malwares');
    expect(node.tagName).toBe('A');
    expect(node.getAttribute('href')).toContain('/dashboard/arsenal/malwares');
    expect(node.className).toContain('noDrag');
  });

  it('falls back to a plain value when the link is null', () => {
    testRender(<WidgetNumber label="Malwares" value={42} drilldownLink={null} />);
    expect(screen.getByTestId('card-number-Malwares').tagName).toBe('DIV');
  });
});
