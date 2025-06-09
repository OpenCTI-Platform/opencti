import { graphql, useFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import Chip from '@mui/material/Chip';
import { AccountBalanceOutlined } from '@mui/icons-material';
import React from 'react';
import { truncate } from '../../../../utils/String';
import { StixCoreObjectSharingListFragment$key } from './__generated__/StixCoreObjectSharingListFragment.graphql';
import { StixCoreObjectSharingListDeleteMutation } from './__generated__/StixCoreObjectSharingListDeleteMutation.graphql';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const objectOrganizationFragment = graphql`
  fragment StixCoreObjectSharingListFragment on StixCoreObject {
    id
    objectOrganization {
      id
      name
    }
  }
`;

const objectOrganizationDeleteMutation = graphql`
  mutation StixCoreObjectSharingListDeleteMutation($id: ID!, $organizationId: [ID!]!) {
    stixCoreObjectEdit(id: $id) {
      restrictionOrganizationDelete(organizationId: $organizationId) {
        id
        ...StixCoreObjectSharingListFragment
      }
    }
  }
`;

interface StixCoreObjectSharingListProps {
  data: StixCoreObjectSharingListFragment$key
  disabled?: boolean
}

const StixCoreObjectSharingList = ({ data, disabled }: StixCoreObjectSharingListProps) => {
  const draftContext = useDraftContext();
  const disabledInDraft = !!draftContext;

  const [deleteOrganization] = useApiMutation<StixCoreObjectSharingListDeleteMutation>(objectOrganizationDeleteMutation);
  const { objectOrganization, id } = useFragment(objectOrganizationFragment, data);
  if (objectOrganization?.length === 0) return null;

  const removeOrganization = (organizationId: string) => {
    deleteOrganization({
      variables: {
        id,
        organizationId: [organizationId],
      },
    });
  };

  return (
    <div>
      {objectOrganization?.map((organization) => (
        <Tooltip key={organization.id} title={organization.name}>
          <Chip
            sx={{
              '&.MuiChip-root': {
                margin: '4px 7px 0 0',
                fontSize: 12,
                lineHeight: '12px',
                height: 28,
                borderRadius: 1,
              },
            }}
            icon={<AccountBalanceOutlined />}
            color="primary"
            variant="outlined"
            label={truncate(organization.name, 15)}
            onDelete={() => removeOrganization(organization.id)}
            disabled={disabled || disabledInDraft}
          />
        </Tooltip>
      ))}
    </div>
  );
};

export default StixCoreObjectSharingList;
