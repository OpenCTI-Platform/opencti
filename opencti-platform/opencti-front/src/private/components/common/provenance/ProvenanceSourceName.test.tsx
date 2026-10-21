import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ProvenanceSourceName from './ProvenanceSourceName';

describe('Name of a provenance source in the Sources card and panel', () => {
  it('should link an author to its entity', () => {
    testRender(<ProvenanceSourceName source={{ source_id: 'author-id', source_kind: 'author', source_name: 'CERT-FR' }} />);
    expect(screen.getByRole('link', { name: 'CERT-FR' }).getAttribute('href')).toEqual('/dashboard/id/author-id');
  });

  it('should render a source without a page describing it as plain text', () => {
    testRender(<ProvenanceSourceName source={{ source_id: 'connector-id', source_kind: 'connector', source_name: 'MITRE ATT&CK' }} />);
    expect(screen.getByText('MITRE ATT&CK')).toBeTruthy();
    expect(screen.queryByRole('link')).toBeNull();
  });
});
