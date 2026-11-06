import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as Yup from 'yup';
import testRender from '../../../../utils/tests/test-render';
import CaseRfiEditionOverview from './CaseRfiEditionOverview';
import type { CaseRfiEditionOverview_case$key } from './__generated__/CaseRfiEditionOverview_case.graphql';

vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  useFragment: (_fragment: unknown, data: unknown) => data,
}));
vi.mock('../../../../utils/hooks/useEntitySettings', () => ({
  useIsMandatoryAttribute: () => ({ mandatoryAttributes: [] }),
  yupShapeConditionalRequired: (shape: Yup.ObjectShape) => shape,
  useDynamicSchemaEditionValidation: (_mandatory: string[], shape: Yup.ObjectShape) => Yup.object(shape),
}));
vi.mock('../../../../utils/hooks/useFormEditor', () => ({ default: () => ({ changeFocus: vi.fn(), fieldPatch: vi.fn() }) }));
vi.mock('../../common/form/StatusField', () => ({ default: ({ scope }: { scope: string }) => <div>Status field {scope}</div> }));
vi.mock('../../../../components/AlertConfidenceForEntity', () => ({ default: () => null }));
vi.mock('../../common/form/OpenVocabField', () => ({ default: () => null }));
vi.mock('../../common/form/ConfidenceField', () => ({ default: () => null }));
vi.mock('../../common/form/ObjectAssigneeField', () => ({ default: () => null }));
vi.mock('../../common/form/ObjectParticipantField', () => ({ default: () => null }));
vi.mock('../../common/form/CreatedByField', () => ({ default: () => null }));
vi.mock('../../common/form/ObjectMarkingField', () => ({ default: () => null }));
vi.mock('../../common/form/CommitMessage', () => ({ default: () => null }));
vi.mock('@components/common/custom_fields/CustomFieldValuesEdition', () => ({ default: () => null }));
vi.mock('../../../../components/fields/markdownField/MarkdownField', () => ({ default: () => null }));
vi.mock('../../../../components/DateTimePickerField', () => ({ default: () => null }));

const makeRfi = (requestAccess: string | null, scope: string | null) => ({
  id: 'rfi-1', name: 'Request Access for entity', revoked: false, description: '', confidence: 50, entity_type: 'Case-Rfi',
  created: '2026-01-01T00:00:00.000Z', information_types: [], severity: null, priority: null, creators: [], x_opencti_stix_ids: [],
  createdBy: null, status: { id: 'status-1', order: 1, template: { name: 'New', color: '#ff0000' } }, workflowEnabled: true,
  objectMarking: [], objectAssignee: [], objectParticipant: [], x_opencti_request_access: requestAccess,
  workflowInstance: scope ? { id: 'instance-1', scope } : null,
}) as unknown as CaseRfiEditionOverview_case$key;

const requestAccess = JSON.stringify({ entities: ['entity-1'], members: ['org-1'], status: 'NEW' });

describe('CaseRfiEditionOverview', () => {
  it('hides the Status field when workflowInstance scope is REQUEST_ACCESS', () => {
    testRender(<CaseRfiEditionOverview caseRef={makeRfi(requestAccess, 'REQUEST_ACCESS')} handleClose={vi.fn()} />);
    expect(screen.queryByText(/Status field/)).toBeNull();
  });

  it('keeps it for legacy request-access RFIs', () => {
    testRender(<CaseRfiEditionOverview caseRef={makeRfi(requestAccess, null)} handleClose={vi.fn()} />);
    expect(screen.getByText('Status field REQUEST_ACCESS')).toBeVisible();
  });

  it('keeps it for ordinary RFIs', () => {
    testRender(<CaseRfiEditionOverview caseRef={makeRfi(null, 'GLOBAL')} handleClose={vi.fn()} />);
    expect(screen.getByText('Status field GLOBAL')).toBeVisible();
  });
});
