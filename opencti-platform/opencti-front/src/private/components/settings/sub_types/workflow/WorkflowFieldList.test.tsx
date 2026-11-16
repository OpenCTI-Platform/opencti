import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { Form, Formik } from 'formik';
import testRender from '../../../../../utils/tests/test-render';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import WorkflowFieldList from './WorkflowFieldList';
import { WorkflowActionType } from './utils';
import type { WorkflowEditionFormValues } from './WorkflowEditionDrawer';

vi.mock('../../../../../utils/hooks/useEnterpriseEdition', () => ({
  default: vi.fn(),
}));

vi.mock('@components/common/form/AuthorizedMembersField', () => ({
  default: () => <div data-testid="authorized-members-field" />,
}));

const shareAction = {
  type: WorkflowActionType.shareRequestedEntities,
  params: { organizations: [{ value: 'AUTHOR', label: 'AUTHOR' }, { value: 'org-1', label: 'Org One' }] },
};
const authorizedMembersAction = { type: WorkflowActionType.updateAuthorizedMembers, params: { authorized_members: [] } };

const renderList = (actionType?: WorkflowActionType) => testRender(
  <Formik initialValues={{ onEnter: [authorizedMembersAction, shareAction] } as unknown as WorkflowEditionFormValues} onSubmit={() => {}}>
    <Form>
      <WorkflowFieldList name="onEnter" actionType={actionType} />
    </Form>
  </Formik>,
);

describe('WorkflowFieldList', () => {
  beforeEach(() => {
    vi.mocked(useEnterpriseEdition).mockReturnValue(true);
  });

  it('shows the AUTHOR organization of a shareRequestedEntities action as "Author (requesting organization)"', () => {
    renderList(WorkflowActionType.shareRequestedEntities);
    expect(screen.getByText('Author (requesting organization)')).toBeInTheDocument();
    expect(screen.getByText('Org One')).toBeInTheDocument();
    expect(screen.queryByText('AUTHOR')).toBeNull();
  });

  it('renders only the actions of the requested type', () => {
    renderList(WorkflowActionType.shareRequestedEntities);
    expect(screen.queryByTestId('authorized-members-field')).toBeNull();
  });

  it('renders every action when no type is requested', () => {
    renderList();
    expect(screen.getByTestId('authorized-members-field')).toBeInTheDocument();
    expect(screen.getByText('Author (requesting organization)')).toBeInTheDocument();
  });
});
