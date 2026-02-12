import { useState } from 'react';
import { Tooltip } from '@mui/material';
import { graphql } from 'relay-runtime';
import { useFragment } from 'react-relay';
import { LockOutlined } from '@mui/icons-material';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import IconButton from '../../../components/common/button/IconButton';
import { useFormatter } from '../../../components/i18n';
import FormAuthorizedMembersDialog from '../common/form/FormAuthorizedMembersDialog';
import { authorizedMembersToOptions, useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import { DraftAuthorizedMembersFragment$key } from '@components/drafts/__generated__/DraftAuthorizedMembersFragment.graphql';

const draftFragment = graphql`
  fragment DraftAuthorizedMembersFragment on DraftWorkspace {
    id
    currentUserAccessRight
    creators {
      id
      name
      entity_type
    }
    authorizedMembers {
      id
      name
      entity_type
      access_right
      member_id
      groups_restriction {
        id
        name
      }
    }
  }
`;

const editAuthorizedMembersMutation = graphql`
  mutation DraftAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]
  ) {
    draftWorkspaceEditAuthorizedMembers(id: $id, input: $input) {
      id
      ...DraftRootFragment
      ...DraftToolbarFragment
    }
  }
`;

interface DraftAuthorizedMembersProps {
  data: DraftAuthorizedMembersFragment$key;
}

const DraftAuthorizedMembers = ({ data }: DraftAuthorizedMembersProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  const {
    id,
    creators,
    authorizedMembers,
    currentUserAccessRight,
  } = useFragment(draftFragment, data);
  const currentAccessRight = useGetCurrentUserAccessRight(currentUserAccessRight);

  return (
    <>
      {currentAccessRight.canManage && (
        <Security needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}>
          <Tooltip title={t_i18n('Authorized members')}>
            <IconButton
              size="default"
              onClick={() => setOpen(true)}
              variant="secondary"
            >
              <LockOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
        </Security>
      )}

      {open && (
        <FormAuthorizedMembersDialog
          id={id}
          mutation={editAuthorizedMembersMutation}
          authorizedMembers={authorizedMembersToOptions(authorizedMembers)}
          open={open}
          handleClose={() => setOpen(false)}
          owner={creators?.[0]}
          canDeactivate
        />
      )}
    </>
  );
};

export default DraftAuthorizedMembers;
