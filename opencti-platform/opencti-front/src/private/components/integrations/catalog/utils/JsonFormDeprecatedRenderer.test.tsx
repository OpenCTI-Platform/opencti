import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import { JsonFormDeprecatedRenderer, jsonFormDeprecatedTester } from './JsonFormDeprecatedRenderer';

const jsonFormsDispatchMock = vi.fn((props: unknown) => <div data-testid="jsonforms-dispatch" data-props={JSON.stringify(props)} />);

vi.mock('@jsonforms/react', () => ({
  JsonFormsDispatch: (props: unknown) => jsonFormsDispatchMock(props),
  withJsonFormsControlProps: (Component: React.ComponentType<unknown>) => Component,
}));

vi.mock('../../../../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (value: string) => value,
  }),
}));

vi.mock('../../../../../components/common/tag/Tag', () => ({
  default: ({
    label,
    tooltipTitle,
  }: {
    label: string;
    tooltipTitle?: string;
  }) => (
    <span data-testid="deprecated-tag" data-tooltip-title={tooltipTitle ?? ''}>
      {label}
    </span>
  ),
}));

describe('JsonFormDeprecatedRenderer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('re-dispatches deprecated enum control with root schema and without recursive deprecated renderer', () => {
    const rootSchema = {
      type: 'object',
      properties: {
        HYBRID_ANALYSIS_MAX_TLP: {
          type: 'string',
          enum: ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'],
          deprecated: true,
          default: 'TLP:AMBER',
        },
      },
    };

    const nonDeprecatedRenderer = {
      tester: () => 1,
      renderer: () => <div>non-deprecated</div>,
    };

    const handleChange = vi.fn();

    testRender(
      <JsonFormDeprecatedRenderer
        id="json-form-deprecated-renderer"
        errors=""
        uischema={{ type: 'Control', scope: '#/properties/HYBRID_ANALYSIS_MAX_TLP' }}
        schema={rootSchema.properties.HYBRID_ANALYSIS_MAX_TLP}
        rootSchema={rootSchema}
        path="HYBRID_ANALYSIS_MAX_TLP"
        enabled={true}
        visible={true}
        renderers={[
          { tester: jsonFormDeprecatedTester, renderer: JsonFormDeprecatedRenderer },
          nonDeprecatedRenderer,
        ]}
        cells={[]}
        label="HYBRID_ANALYSIS_MAX_TLP"
        description="Use HYBRID_ANALYSIS_SANDBOX_MAX_TLP instead."
        data="TLP:AMBER+STRICT"
        handleChange={handleChange}
      />,
    );

    expect(screen.getByText('Deprecated')).toBeInTheDocument();
    expect(screen.getByTestId('jsonforms-dispatch')).toBeInTheDocument();

    expect(jsonFormsDispatchMock).toHaveBeenCalled();
    const [firstCallArg] = jsonFormsDispatchMock.mock.calls[0] as [unknown];
    const dispatchProps = firstCallArg as {
      schema: unknown;
      path: string;
      renderers: Array<{ tester: unknown }>;
    };

    expect(dispatchProps.schema).toBe(rootSchema);
    expect(dispatchProps.path).toBe('');
    expect(dispatchProps.renderers).toHaveLength(1);
    expect(dispatchProps.renderers[0].tester).toBe(nonDeprecatedRenderer.tester);
  });

  it('formats uppercase underscore tokens in deprecated description', () => {
    const rootSchema = {
      type: 'object',
      properties: {
        HYBRID_ANALYSIS_MAX_TLP: {
          type: 'string',
          deprecated: true,
          default: 'TLP:AMBER',
        },
      },
    };

    const handleChange = vi.fn();

    testRender(
      <JsonFormDeprecatedRenderer
        id="json-form-deprecated-renderer"
        errors=""
        uischema={{ type: 'Control', scope: '#/properties/HYBRID_ANALYSIS_MAX_TLP' }}
        schema={rootSchema.properties.HYBRID_ANALYSIS_MAX_TLP}
        rootSchema={rootSchema}
        path="HYBRID_ANALYSIS_MAX_TLP"
        enabled={true}
        visible={true}
        renderers={[]}
        cells={[]}
        label="HYBRID_ANALYSIS_MAX_TLP"
        description="Use HYBRID_ANALYSIS_SANDBOX_MAX_TLP instead. (removal scheduled for 2026-12-31)"
        data="TLP:AMBER+STRICT"
        handleChange={handleChange}
      />,
    );

    expect(screen.getByTestId('deprecated-tag')).toHaveAttribute(
      'data-tooltip-title',
      'Use HYBRID ANALYSIS SANDBOX MAX TLP instead. (removal scheduled for 2026-12-31)',
    );
  });
});
