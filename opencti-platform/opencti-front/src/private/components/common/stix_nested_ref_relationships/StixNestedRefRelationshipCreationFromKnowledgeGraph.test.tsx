import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import StixNestedRefRelationshipCreationFromKnowledgeGraph from './StixNestedRefRelationshipCreationFromKnowledgeGraph';

const props = {
  nestedRelationExist: false,
  openCreateNested: false,
  nestedEnabled: true,
  relationFromObjects: [{ id: 'from', entity_type: 'Malware' }],
  relationToObjects: [{ id: 'to', entity_type: 'Intrusion-Set' }],
  handleSetNestedRelationExist: vi.fn(),
  handleOpenCreateNested: vi.fn(),
};

describe('StixNestedRefRelationshipCreationFromKnowledgeGraph', () => {
  it('says why the tool is disabled without two entities to link', () => {
    testRender(<StixNestedRefRelationshipCreationFromKnowledgeGraph {...props} nestedEnabled={false} />);
    const tool = screen.getByRole('button', { name: 'Create a nested relationship' });
    expect(tool).toHaveAttribute('aria-disabled', 'true');
    expect(tool).toHaveAccessibleDescription('Select the entities to link first');
  });

  it('says why the tool is disabled while a nested relationship is being created', () => {
    testRender(<StixNestedRefRelationshipCreationFromKnowledgeGraph {...props} openCreateNested />);
    const tool = screen.getByRole('button', { name: 'Create a nested relationship' });
    expect(tool).toHaveAttribute('aria-disabled', 'true');
    expect(tool).toHaveAccessibleDescription('A nested relationship is being created');
  });
});
