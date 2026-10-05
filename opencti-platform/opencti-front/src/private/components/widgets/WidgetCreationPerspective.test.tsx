import { describe, it, expect, vi } from 'vitest';
import { emptyFilterGroup, SELF_ID } from '../../../utils/filters/filtersUtils';
import { containerTypes } from '../../../utils/hooks/useAttributes';
import testRender from '../../../utils/tests/test-render';
import WidgetCreationPerspective, { buildInitialFilters } from './WidgetCreationPerspective';

const { mockUseGranted } = vi.hoisted(() => ({ mockUseGranted: vi.fn() }));

vi.mock('../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useGranted')>()),
  default: mockUseGranted,
}));
vi.mock('../../../utils/hooks/useAttributes', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../utils/hooks/useAttributes')>();
  return { ...original, default: () => ({ containerTypes: original.containerTypes }) };
});
vi.mock('./WidgetConfigContext', () => ({
  useWidgetConfigContext: () => ({
    host: { kind: 'workspace' },
    config: { widget: { type: 'number', dataSelection: [] } },
    setStep: vi.fn(),
    setConfigWidget: vi.fn(),
  }),
}));

describe('WidgetCreationPerspective', () => {
  it('offers the intelligence sources perspective of a dashboard with the connectors or ingestion capability', () => {
    mockUseGranted.mockReturnValue(true);
    const { getByTestId } = testRender(<WidgetCreationPerspective />);
    expect(mockUseGranted).toHaveBeenCalledWith(['MODULES', 'INGESTION']);
    expect(getByTestId('sources-widget-perspective')).toBeTruthy();
  });

  it('does not offer the intelligence sources perspective without the capability', () => {
    mockUseGranted.mockReturnValue(false);
    const { getByTestId, queryByTestId } = testRender(<WidgetCreationPerspective />);
    expect(getByTestId('entities-widget-perspective')).toBeTruthy();
    expect(queryByTestId('sources-widget-perspective')).toBeNull();
  });
});

describe('buildInitialFilters', () => {
  describe('when host is a fintel template', () => {
    describe('when host entity type is a container', () => {
      describe('when perspective is entities', () => {
        it('preconfigures an objects filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'fintelTemplate',
              fintelEntityType: 'Report',
              fintelWidgets: [],
              fintelEditorValue: '',
            } as const,
            'entities',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'objects',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });

      describe('when perspective is relationships', () => {
        it('preconfigures an objects filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'fintelTemplate',
              fintelEntityType: 'Report',
              fintelWidgets: [],
              fintelEditorValue: '',
            } as const,
            'relationships',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'objects',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });
    });

    describe('when host entity type is not a container', () => {
      describe('when perspective is entities', () => {
        it('preconfigures a regardingOf filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'fintelTemplate',
              fintelEntityType: 'Malware',
              fintelWidgets: [],
              fintelEditorValue: '',
            } as const,
            'entities',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'regardingOf',
              values: [{ key: 'id', values: [SELF_ID] }],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });

      describe('when perspective is relationships', () => {
        it('preconfigures a fromId filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'fintelTemplate',
              fintelEntityType: 'Malware',
              fintelWidgets: [],
              fintelEditorValue: '',
            } as const,
            'relationships',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'fromId',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });
    });
  });

  describe('when host is a custom view', () => {
    describe('when host entity type is a container', () => {
      describe('when perspective is entities', () => {
        it('preconfigures an objects filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'fintelTemplate',
              fintelEntityType: 'Report',
              fintelWidgets: [],
              fintelEditorValue: '',
            } as const,
            'entities',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'objects',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });

      describe('when perspective is relationships', () => {
        it('preconfigures an objects filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'fintelTemplate',
              fintelEntityType: 'Report',
              fintelWidgets: [],
              fintelEditorValue: '',
            } as const,
            'relationships',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'objects',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });

      describe('when perspective is audits', () => {
        it('preconfigures an objects filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'fintelTemplate',
              fintelEntityType: 'Report',
              fintelWidgets: [],
              fintelEditorValue: '',
            } as const,
            'audits',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'objects',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });
    });

    describe('when host entity type is not a container', () => {
      describe('when perspective is entities', () => {
        it('preconfigures a regardingOf filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'custom-view',
              customViewTargetEntityType: 'Malware',
            } as const,
            'entities',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'regardingOf',
              values: [{ key: 'id', values: [SELF_ID] }],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });

      describe('when perspective is relationships', () => {
        it('preconfigures a fromOrToId filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'custom-view',
              customViewTargetEntityType: 'Malware',
            } as const,
            'relationships',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'fromOrToId',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });

      describe('when perspective is audits', () => {
        it('preconfigures a contextEntityId filter with SELF_ID value', () => {
          const filters = buildInitialFilters(
            containerTypes,
            {
              kind: 'custom-view',
              customViewTargetEntityType: 'Malware',
            } as const,
            'audits',
          );
          expect(filters).toStrictEqual({
            mode: 'and',
            filters: [{
              id: expect.any(String),
              key: 'contextEntityId',
              values: [SELF_ID],
              operator: 'eq',
              mode: 'or',
            }],
            filterGroups: [],
          });
        });
      });
    });
  });

  describe('when host is a workspace', () => {
    describe('when perspective is entities', () => {
      it('does not preconfigure filters', () => {
        const filters = buildInitialFilters(
          containerTypes,
          {
            kind: 'workspace',
          } as const,
          'entities',
        );
        expect(filters).toStrictEqual(emptyFilterGroup);
      });
    });

    describe('when perspective is relationships', () => {
      it('does not preconfigure filters', () => {
        const filters = buildInitialFilters(
          containerTypes,
          {
            kind: 'workspace',
          } as const,
          'relationships',
        );
        expect(filters).toStrictEqual(emptyFilterGroup);
      });
    });

    describe('when perspective is audits', () => {
      it('does not preconfigure filters', () => {
        const filters = buildInitialFilters(
          containerTypes,
          {
            kind: 'workspace',
          } as const,
          'audits',
        );
        expect(filters).toStrictEqual(emptyFilterGroup);
      });
    });
  });
});
