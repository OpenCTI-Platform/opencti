import React, { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ContentMappingReviewPanel, { ReviewTab } from './ContentMappingReviewPanel';
import { buildReviewItems, EMPTY_REVIEW, MappableEntity } from './contentMappingModel';

vi.mock('./MappingEnrichmentDialog', () => ({ default: () => null }));

const entity = (standardId: string, entityType: string, name: string): MappableEntity => ({ id: `${standardId}-id`, standard_id: standardId, entity_type: entityType, representative: { main: name } });
const apt41 = entity('intrusion-set--1', 'Intrusion-Set', 'APT41');
const deedrat = entity('malware--2', 'Malware', 'DeedRAT');

const items = buildReviewItems({
  mapping: { apt41: apt41.standard_id, deedrat: deedrat.standard_id },
  review: { ...EMPTY_REVIEW, ignored: { frp: { value: 'FRP', entityType: 'Tool' } } },
  objects: [apt41, deedrat],
  suggestions: {
    mapped: [],
    unresolved: [
      { matchedString: '45.77.120.14', standardId: 'ipv4-addr--3', entityType: 'IPv4-Addr' },
      { matchedString: 'update-check[.]net', standardId: 'domain-name--4', entityType: 'Domain-Name' },
    ],
  },
});

const Harness = (props: Partial<React.ComponentProps<typeof ContentMappingReviewPanel>>) => {
  const [tab, setTab] = useState<ReviewTab>('toReview');
  const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
  return (
    <ContentMappingReviewPanel
      items={items}
      counts={{ '45.77.120.14': 2 }}
      relations={[]}
      tab={tab}
      onTabChange={setTab}
      selectedKeys={selectedKeys}
      onSelectedKeysChange={setSelectedKeys}
      activeKey={null}
      onActiveKeyChange={vi.fn()}
      sourceLabel={(s) => s}
      analysisPending={false}
      onValidate={vi.fn()}
      onIgnore={vi.fn()}
      onRestore={vi.fn()}
      onUnmap={vi.fn()}
      onChangeType={vi.fn()}
      onCreateRelation={vi.fn()}
      onActiveRelationChange={vi.fn()}
      {...props}
    />
  );
};

describe('ContentMappingReviewPanel', () => {
  it('should count the objects per tab and describe the new ones', () => {
    testRender(<Harness />);
    expect(screen.getByRole('tab', { name: 'To review · 2' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Mapped · 2' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Ignored · 1' })).toBeInTheDocument();
    expect(screen.getByText('New · 2 occurrences')).toBeInTheDocument();
    expect(screen.getByText('update-check.net')).toBeInTheDocument();
    expect(screen.getByText(/auto refang/)).toBeInTheDocument();
  });

  it('should validate the selected suggestions in bulk', async () => {
    const onValidate = vi.fn();
    const { user } = testRender(<Harness onValidate={onValidate} />);
    await user.click(screen.getByRole('checkbox', { name: 'Select all' }));
    await user.click(screen.getByRole('button', { name: 'Validate' }));
    expect(onValidate).toHaveBeenCalledWith(expect.arrayContaining([
      expect.objectContaining({ key: '45.77.120.14' }),
      expect.objectContaining({ key: 'update-check[.]net' }),
    ]));
  });

  it('should offer a relationship between two mapped objects', async () => {
    const onCreateRelation = vi.fn();
    const { user } = testRender(<Harness onCreateRelation={onCreateRelation} />);
    await user.click(screen.getByRole('tab', { name: 'Mapped · 2' }));
    await user.click(screen.getByTestId('mapping-row-apt41'));
    expect(screen.queryByRole('button', { name: 'Create a relationship' })).not.toBeInTheDocument();
    await user.click(screen.getByTestId('mapping-row-deedrat'));
    await user.click(screen.getByRole('button', { name: 'Create a relationship' }));
    expect(onCreateRelation).toHaveBeenCalled();
  });

  it('should filter by family', async () => {
    const { user } = testRender(<Harness />);
    await user.click(screen.getByText('Entities 0'));
    expect(screen.queryByTestId('mapping-row-45.77.120.14')).not.toBeInTheDocument();
  });
});
