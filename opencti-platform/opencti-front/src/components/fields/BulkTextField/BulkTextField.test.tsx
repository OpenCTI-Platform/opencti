import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { Field, Formik } from 'formik';
import testRender from '../../../utils/tests/test-render';
import BulkTextField from './BulkTextField';
import { BulkCreationFeedback, CreationFeedbackContext } from '../../../utils/hooks/useCreationFeedback';

const bulkCreation: BulkCreationFeedback = {
  onBulkStart: vi.fn(),
  onBulkCompleted: vi.fn(),
  onBulkEnd: vi.fn(),
  containerType: 'Report',
  progress: null,
  resultMessage: null,
};

const field = (bulkType?: 'entities' | 'observables') => (
  <Formik initialValues={{ name: 'one\ntwo' }} onSubmit={vi.fn()}>
    <Field component={BulkTextField} name="name" label="Name" bulkType={bulkType} />
  </Formik>
);

describe('BulkTextField', () => {
  it('says how many entities will be created', () => {
    testRender(field());
    expect(screen.getByText('2 entities will be created')).toBeDefined();
  });

  it('says they will also be added to the container in its add panel', () => {
    testRender(
      <CreationFeedbackContext.Provider value={{ silenceCreationSuccess: true, bulkCreation }}>
        {field()}
      </CreationFeedbackContext.Provider>,
    );
    expect(screen.getByText('2 entities will be created and added to the Report')).toBeDefined();
  });

  it('says the same for observables', () => {
    testRender(
      <CreationFeedbackContext.Provider value={{ silenceCreationSuccess: true, bulkCreation }}>
        {field('observables')}
      </CreationFeedbackContext.Provider>,
    );
    expect(screen.getByText('2 observables will be created and added to the Report')).toBeDefined();
  });
});
