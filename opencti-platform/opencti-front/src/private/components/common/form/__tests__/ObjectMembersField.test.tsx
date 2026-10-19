import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, screen } from '@testing-library/react';
import { Formik } from 'formik';
import testRender from '../../../../../utils/tests/test-render';
import ObjectMembersField from '../ObjectMembersField';

type Member = { id: string; entity_type: string; name: string };

// Each search returns a promise resolved manually by the test, to control the response order
const pendingSearches: { search: string; resolve: (members: Member[]) => void }[] = [];

vi.mock('../../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../../relay/environment')>();
  return {
    ...actual,
    fetchQuery: (_query: unknown, variables: { search: string }) => ({
      toPromise: () => new Promise((resolve) => {
        pendingSearches.push({
          search: variables.search,
          resolve: (members: Member[]) => resolve({ members: { edges: members.map((node) => ({ node })) } }),
        });
      }),
    }),
  };
});

const longName = 'An organization with a very long name that goes beyond forty characters Acme';

const renderField = (withDynamicKeys = false) => testRender(
  <Formik initialValues={{ members: [] }} onSubmit={() => {}}>
    <ObjectMembersField name="members" multiple withDynamicKeys={withDynamicKeys} />
  </Formik>,
);

const resolveSearch = async (search: string, members: Member[]) => {
  const pending = pendingSearches.find((p) => p.search === search);
  expect(pending).toBeDefined();
  await act(async () => pending?.resolve(members));
};

const optionLabels = () => screen.queryAllByRole('option').map((o) => o.textContent);

describe('ObjectMembersField', () => {
  beforeEach(() => {
    pendingSearches.length = 0;
  });

  it('keeps backend results even when the match is beyond the truncated label', async () => {
    const { user } = renderField();
    await user.type(screen.getByRole('combobox'), 'Acme');
    await resolveSearch('Acme', [{ id: 'org-1', entity_type: 'Organization', name: longName }]);
    expect(optionLabels()).toContain(longName);
  });

  it('filters dynamic options by the typed text', async () => {
    const { user } = renderField(true);
    await user.type(screen.getByRole('combobox'), 'Assig');
    await resolveSearch('Assig', []);
    const labels = optionLabels();
    expect(labels).toContain('Assignees');
    expect(labels).not.toContain('Creators');
    expect(labels).not.toContain('Participants');
  });

  it('ignores a stale search response resolving after the latest one', async () => {
    const { user } = renderField();
    await user.type(screen.getByRole('combobox'), 'ab');
    await resolveSearch('ab', [{ id: 'user-ab', entity_type: 'User', name: 'Latest result' }]);
    await resolveSearch('a', [{ id: 'user-a', entity_type: 'User', name: 'Stale result' }]);
    const labels = optionLabels();
    expect(labels).toContain('Latest result');
    expect(labels).not.toContain('Stale result');
  });
});
