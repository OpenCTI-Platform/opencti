import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../tests/test-render';
import { isVocabularyCategory } from '../vocabulary/vocabularyCategories';
import { NON_VOCABULARY_TYPES, openVocabListCategories, openVocabSingleCategories } from './widgetOpenVocabRendererUtils';
import {
  THREAT_ACTOR_GROUP_SOPHISTICATION_CATEGORY,
  THREAT_ACTOR_INDIVIDUAL_SOPHISTICATION_CATEGORY,
} from './widgetCustomAttributesRendererUtils';
import ItemOpenVocab from '../../components/ItemOpenVocab';

describe('widget open vocabulary renderers', () => {
  const categories = [
    ...Object.values(openVocabSingleCategories),
    ...Object.values(openVocabListCategories),
    THREAT_ACTOR_GROUP_SOPHISTICATION_CATEGORY,
    THREAT_ACTOR_INDIVIDUAL_SOPHISTICATION_CATEGORY,
  ].filter((category) => !NON_VOCABULARY_TYPES.includes(category));

  it.each(categories)('passes %s, a VocabularyCategory enum member', (category) => {
    expect(isVocabularyCategory(category)).toBe(true);
  });
});

describe('isVocabularyCategory', () => {
  it('rejects names outside the enum', () => {
    expect(isVocabularyCategory('threat-actor-individual-sophistication-ov')).toBe(false);
    expect(isVocabularyCategory('observable_types_ov')).toBe(false);
    expect(isVocabularyCategory('')).toBe(false);
    expect(isVocabularyCategory(undefined)).toBe(false);
  });
});

describe('ItemOpenVocab chip with a type outside the enum', () => {
  it('renders the plain chip without sending a vocabulary query', () => {
    const { relayEnv } = testRender(
      <ItemOpenVocab displayMode="chip" type="threat-actor-individual-sophistication-ov" value="expert" />,
    );
    expect(screen.getByText('expert')).toBeInTheDocument();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('queries the vocabulary of an enum member', () => {
    const { relayEnv } = testRender(
      <ItemOpenVocab displayMode="chip" type="threat_actor_individual_sophistication_ov" value="expert" />,
    );
    const operations = relayEnv.mock.getAllOperations();
    expect(operations).toHaveLength(1);
    expect(operations[0].request.variables).toEqual({ category: 'threat_actor_individual_sophistication_ov' });
  });
});
