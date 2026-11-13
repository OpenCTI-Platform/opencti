import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixCoreObjectKnowledgeBar from './StixCoreObjectKnowledgeBar';
import fragmentNode from './__generated__/StixCoreObjectKnowledgeBar_stixCoreObject.graphql';

const { fragmentData } = vi.hoisted(() => ({
  fragmentData: { current: {} as Record<string, unknown> },
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return { ...actual, useFragment: () => fragmentData.current };
});

const renderBar = (availableSections: string[]) => testRender(
  <StixCoreObjectKnowledgeBar
    stixCoreObjectLink="/dashboard/techniques/attack_patterns/ap-1/knowledge"
    availableSections={availableSections}
    data={{} as never}
  />,
  {
    userContext: createMockUserContext({
      bannerSettings: { bannerHeightNumber: 0 },
      schema: { scos: [] },
    }),
  },
);

describe('StixCoreObjectKnowledgeBar procedures', () => {
  beforeEach(() => {
    fragmentData.current = {
      id: 'ap-1',
      relationshipsWithoutRelatedToDistribution: [
        { label: 'Procedure', value: 3 },
        { label: 'Course-Of-Action', value: 2 },
        { label: 'Vulnerability', value: 4 },
      ],
      relationshipsRelatedDistribution: [],
      stixCoreObjectsDistribution: [],
      indicatorsDistribution: [],
    };
  });

  it('should show a Procedures item with its count when the section is available', () => {
    renderBar(['procedures']);
    const link = screen.getByRole('link', { name: /Procedures \(3\)/ });
    expect(link.getAttribute('href')).toBe('/dashboard/techniques/attack_patterns/ap-1/knowledge/procedures');
  });

  it('should not show the Procedures item when the section is not available', () => {
    renderBar(['malwares']);
    expect(screen.queryByRole('link', { name: /Procedures/ })).toBeNull();
  });

  it('should count courses of action and vulnerabilities from the distribution', () => {
    renderBar(['courses_of_action', 'vulnerabilities']);
    expect(screen.getByRole('link', { name: /Courses of action \(2\)/ })).toBeDefined();
    expect(screen.getByRole('link', { name: /Vulnerabilities \(4\)/ })).toBeDefined();
  });

  it('should request the relationship types that link procedures', () => {
    const query = JSON.stringify(fragmentNode);
    ['implements-technique', 'exploits', 'mitigates'].forEach((type) => {
      expect(query).toContain(`"${type}"`);
    });
  });
});
