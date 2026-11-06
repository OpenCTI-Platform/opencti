import { screen } from '@testing-library/react';
import { Formik } from 'formik';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as useGrantedModule from '../../../../utils/hooks/useGranted';
import { DeferredCreationContext } from '../../../../utils/hooks/useDeferredCreation';
import testRender from '../../../../utils/tests/test-render';
import ObjectLabelField from './ObjectLabelField';

// The create affordance is what is under test: reduce the combobox to whether it was given one
vi.mock('../../../../components/ComboboxField', () => ({
  __esModule: true,
  default: ({ openCreate }: { openCreate?: () => void }) => <div data-testid="combobox" data-can-create={String(!!openCreate)} />,
}));

vi.mock('../../settings/labels/LabelCreation', () => ({ __esModule: true, default: () => null }));

const useGrantedSpy = vi.spyOn(useGrantedModule, 'default');

const renderField = (isDeferredMode?: boolean, toDraft?: boolean) => {
  const field = (
    <Formik initialValues={{ objectLabel: [] }} onSubmit={() => {}}>
      <ObjectLabelField name="objectLabel" />
    </Formik>
  );
  return testRender(isDeferredMode === undefined
    ? field
    : (
        <DeferredCreationContext.Provider value={{ isDeferredMode, toDraft, captureInput: vi.fn(), registerPending: vi.fn(), getPending: vi.fn() }}>
          {field}
        </DeferredCreationContext.Provider>
      ));
};

const canCreate = () => screen.getByTestId('combobox').getAttribute('data-can-create');

describe('ObjectLabelField', () => {
  beforeEach(() => {
    useGrantedSpy.mockReset();
  });

  it('offers to create a label outside a form intake, whatever the rights', () => {
    useGrantedSpy.mockReturnValue(false);
    renderField();
    expect(canCreate()).toBe('true');
  });

  it('offers to create a label in a form intake to a user allowed to manage labels', () => {
    useGrantedSpy.mockImplementation((capabilities: string[]) => capabilities.includes(useGrantedModule.SETTINGS_SETLABELS));
    renderField(true);
    expect(canCreate()).toBe('true');
  });

  it('does not offer to create a label in a form intake to a user who cannot manage labels', () => {
    useGrantedSpy.mockReturnValue(false);
    renderField(true);
    expect(canCreate()).toBe('false');
  });

  it('counts the right to manage labels in the draft scope only for a submission to a draft', () => {
    // a user in main who can manage labels in the draft scope only
    useGrantedSpy.mockImplementation((_capabilities, _matchAll, options) => !!options?.capabilitiesInDraft?.includes(useGrantedModule.SETTINGS_SETLABELS));
    renderField(true, true);
    expect(canCreate()).toBe('true');
  });

  it('does not count the right to manage labels in the draft scope for a submission to main', () => {
    useGrantedSpy.mockImplementation((_capabilities, _matchAll, options) => !!options?.capabilitiesInDraft?.includes(useGrantedModule.SETTINGS_SETLABELS));
    renderField(true, false);
    expect(canCreate()).toBe('false');
  });
});
