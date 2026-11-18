import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../tests/test-render';
import ItemOpenVocab from '../../components/ItemOpenVocab';

// The categories the backend serves (vocabularyCategories); this module otherwise preloads its query on the application environment at import time.
vi.mock('../hooks/useVocabularyCategory', () => {
  const categories = ['malware_type_ov', 'threat_actor_individual_sophistication_ov'];
  return {
    default: () => ({
      findCategory: (type: string) => categories.find((c) => c === type.toLowerCase().replaceAll('-', '_')),
    }),
  };
});

describe('ItemOpenVocab chip', () => {
  it('renders the plain chip without sending a vocabulary query when no category matches the type', () => {
    const { relayEnv } = testRender(
      <ItemOpenVocab displayMode="chip" type="observable_types_ov" value="IPv4-Addr" />,
    );
    expect(screen.getByText('IPv4-Addr')).toBeInTheDocument();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('queries the vocabulary of a known category', () => {
    const { relayEnv } = testRender(
      <ItemOpenVocab displayMode="chip" type="threat_actor_individual_sophistication_ov" value="expert" />,
    );
    const operations = relayEnv.mock.getAllOperations();
    expect(operations).toHaveLength(1);
    expect(operations[0].request.variables).toEqual({ category: 'threat_actor_individual_sophistication_ov' });
  });

  it('queries the normalized category of a hyphenated type', () => {
    const { relayEnv } = testRender(
      <ItemOpenVocab displayMode="chip" type="malware-type-ov" value="ransomware" />,
    );
    const operations = relayEnv.mock.getAllOperations();
    expect(operations).toHaveLength(1);
    expect(operations[0].request.variables).toEqual({ category: 'malware_type_ov' });
  });
});
