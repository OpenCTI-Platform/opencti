import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import DisseminationAssuranceLink from './DisseminationAssuranceLink';

describe('DisseminationAssuranceLink', () => {
  it('should open the overview of the Dissemination assurance area', () => {
    testRender(<DisseminationAssuranceLink />);
    const link = screen.getByTestId('dissemination-assurance-link');
    expect(link.getAttribute('href')).toEqual('/dashboard/defense/assurance/overview');
    expect(link.textContent).toContain('Dissemination assurance');
  });
});
