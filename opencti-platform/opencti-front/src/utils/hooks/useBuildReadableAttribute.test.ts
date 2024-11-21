import { afterAll, beforeAll, describe, it, vi, expect } from 'vitest';
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

    const { readableAttribute: stringAttribute } = buildReadableAttribute('Report', { attribute: 'entity_type' });
    expect(stringAttribute).toEqual('Report');
    const { readableAttribute: dateAttribute } = buildReadableAttribute('2024-11-07T14:42:41.000Z', { attribute: 'published' });
    expect(dateAttribute).toEqual('2024-11-07');
    const { readableAttribute: listAttribute } = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value' });
    expect(listAttribute).toEqual('label1, label2');
    const { readableAttribute: listAttribute2 } = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value', displayStyle: 'text' });
    expect(listAttribute2).toEqual('label1, label2');
    const { readableAttribute: emptyListAttribute } = buildReadableAttribute([], { attribute: 'objectLabel.value', displayStyle: 'text' });
    expect(emptyListAttribute).toEqual('');
    const { readableAttribute: listAttributeWithChips } = buildReadableAttribute(['label1', 'label2'], { attribute: 'objectLabel.value', displayStyle: 'list' });
    expect(listAttributeWithChips).toEqual('<ul><li>label1</li><li>label2</li></ul>');
    const { readableAttribute: emptyListAttributeWithChips } = buildReadableAttribute([], { attribute: 'objectLabel.value', displayStyle: 'chip' });
    expect(emptyListAttributeWithChips).toEqual('');
    const { readableAttribute: nullAttribute } = buildReadableAttribute(null, { attribute: 'objectLabel.value' });
    expect(nullAttribute).toEqual('null');
    const { readableAttribute: booleanAttribute } = buildReadableAttribute(true, { attribute: 'revoked' });
    expect(booleanAttribute).toEqual('true');
    const { readableAttribute: textAttribute, isElement } = buildReadableAttribute('My description', { attribute: 'description' });
    expect(textAttribute).toEqual('<div class="markdown"><p>My description</p></div>');
    expect(isElement).toEqual(false);
    const { isElement: isElement2 } = buildReadableAttribute('My description', { attribute: 'description' }, true);
    expect(isElement2).toEqual(true);
  });
});
