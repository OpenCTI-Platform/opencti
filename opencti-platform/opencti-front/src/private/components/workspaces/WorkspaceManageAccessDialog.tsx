import React, { FunctionComponent } from 'react';
import { FormikHelpers } from 'formik/dist/types';
import { graphql, useFragment } from 'react-relay';
import FormAuthorizedMembers, { FormAuthorizedMembersInputs } from '@components/common/form/FormAuthorizedMembers';
import { InvestigationGraph_fragment$data } from '@components/workspaces/investigations/__generated__/InvestigationGraph_fragment.graphql';
import { WorkspaceManageAccessDialog_authorizedMembers$key } from './__generated__/WorkspaceManageAccessDialog_authorizedMembers.graphql';
import { handleErrorInForm } from '../../../relay/environment';
import { authorizedMembersToOptions } from '../../../utils/authorizedMembers';
import useApiMutation from '../../../utils/hooks/useApiMutation';

const workspaceManageAccessDialogEditAuthorizedMembersMutation = graphql`
  mutation WorkspaceManageAccessDialogEditAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]!
  ) {
    workspaceEditAuthorizedMembers(id: $id, input: $input) {
      id
      ...WorkspaceManageAccessDialog_authorizedMembers
    }
  }
`;

const workspaceManageAccessDialogAuthorizedMembersFragment = graphql`
  fragment WorkspaceManageAccessDialog_authorizedMembers on Workspace {
    authorizedMembers {
      id
      member_id
      name
      entity_type
      access_right
      groups_restriction {
        id
        name
      }
    }
  }
`;

interface WorkspaceManageAccessDialogProps {
  workspaceId: string;
  authorizedMembersData: WorkspaceManageAccessDialog_authorizedMembers$key;
  owner: InvestigationGraph_fragment$data['owner'];
  handleClose: () => void;
  open: boolean;
}

const WorkspaceManageAccessDialog: FunctionComponent<
WorkspaceManageAccessDialogProps
> = ({ workspaceId, authorizedMembersData, owner, handleClose, open }) => {
  const [commit] = useApiMutation(
    workspaceManageAccessDialogEditAuthorizedMembersMutation,
  );
  const data = useFragment<WorkspaceManageAccessDialog_authorizedMembers$key>(
    workspaceManageAccessDialogAuthorizedMembersFragment,
    authorizedMembersData,
  );
  const getInitialAuthorizedMembers = () => {
    const initialAuthorizedMembers = authorizedMembersToOptions(data?.authorizedMembers) ?? [];
    if (initialAuthorizedMembers.length < 1) {
      // empty, no restricted access
      // add owner as admin
      if (owner) {
        initialAuthorizedMembers.push({
          value: owner.id,
          label: owner.name,
          type: owner.entity_type,
          accessRight: 'admin',
          groupsRestriction: [],
        });
      }
    }
    return initialAuthorizedMembers;
  };
  const onSubmitForm = (
    values: FormAuthorizedMembersInputs,
    {
      setSubmitting,
      resetForm,
      setErrors,
    }: FormikHelpers<FormAuthorizedMembersInputs>,
  ) => {
    const finalValues = (values.authorizedMembers ?? [])
      .filter((v) => v.accessRight !== 'none')
      .filter((item, index, array) => {
        return (
          array.findIndex((member) => member.value === item.value) === index
        );
      })
      .map((member) => {
        return {
          id: member.value,
          access_right: member.accessRight,
        };
      });
    commit({
      variables: {
        id: workspaceId,
        input: finalValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };
  return (
    <FormAuthorizedMembers
      existingAccessRules={getInitialAuthorizedMembers()}
      open={open}
      handleClose={handleClose}
      onSubmit={onSubmitForm}
      owner={owner ?? undefined}
      showAllMembersLine={true}
    />
  );
};

export default WorkspaceManageAccessDialog;
