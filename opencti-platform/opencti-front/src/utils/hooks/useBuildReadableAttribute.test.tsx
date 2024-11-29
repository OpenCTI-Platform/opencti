import { afterAll, beforeAll, describe, it, vi, expect } from 'vitest';
import React from 'react';
import * as filterUtils from '../filters/filtersUtils';
import { testRenderHook } from '../tests/test-render';
import useBuildReadableAttribute from './useBuildReadableAttribute';
import { FilterDefinition } from './useAuth';

describe('Hook: useBuildReadableAttribute', () => {
  beforeAll(() => {
    vi.spyOn(filterUtils, 'useBuildFilterKeysMapFromEntityType').mockImplementation(() => new Map([
      ['entity_type', { type: 'string' } as FilterDefinition],
      ['published', { type: 'date' } as FilterDefinition],
      ['revoked', { type: 'boolean' } as FilterDefinition],
      ['description', { type: 'text' } as FilterDefinition],
    ]));
  });
  afterAll(() => {
    vi.restoreAllMocks();
  });

  it('should display readable attribute', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    const stringAttribute = buildReadableAttribute('Report', { attribute: 'entity_type' });
    expect(stringAttribute).toEqual('Report');
    const dateAttribute = buildReadableAttribute('2024-11-07T14:42:41.000Z', { attribute: 'published' });
    expect(dateAttribute).toEqual('2024-11-07');
    const listAttribute = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value' });
    expect(listAttribute).toEqual('label1, label2');
    const listAttribute2 = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value', displayStyle: 'text' });
    expect(listAttribute2).toEqual('label1, label2');
    const emptyListAttribute = buildReadableAttribute([], { attribute: 'objectLabel.value', displayStyle: 'text' });
    expect(emptyListAttribute).toEqual('');
    const listAttributeWithChips = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value', displayStyle: 'list' });
    expect(listAttributeWithChips).toEqual('<ul><li>label1</li><li>label2</li></ul>');
    const emptyListAttributeWithChips = buildReadableAttribute([], { attribute: 'objectLabel.value', displayStyle: 'chip' });
    expect(emptyListAttributeWithChips).toEqual('');
    const nullAttribute = buildReadableAttribute(null, { attribute: 'objectLabel.value' });
    expect(nullAttribute).toEqual('null');
    const booleanAttribute = buildReadableAttribute(true, { attribute: 'revoked' });
    expect(booleanAttribute).toEqual('true');
  });
  it('should remove code bringing security issues like xss', () => {
    const { hook } = testRenderHook(() => useBuildReadableAttribute());
    const { buildReadableAttribute } = hook.result.current;

    const result = (<div dangerouslySetInnerHTML={{ __html: '<img src="x">' }} />);

    const textAttribute1 = buildReadableAttribute('<img src="x" onerror="alert(\'not happening\')">', { attribute: 'description' });
    expect(typeof textAttribute1).toEqual('object');
    expect(textAttribute1).toEqual(result);

    const textAttribute2 = buildReadableAttribute('<img src="x">', { attribute: 'description' });
    expect(typeof textAttribute2).toEqual('object');
    expect(textAttribute2).toEqual(result);
  });
});
