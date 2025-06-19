import { graphql, useFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import Chip from '@mui/material/Chip';
import { AccountBalanceOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { truncate } from '../../../../utils/String';
import { StixCoreObjectSharingListFragment$key } from './__generated__/StixCoreObjectSharingListFragment.graphql';
import { StixCoreObjectSharingListDeleteMutation } from './__generated__/StixCoreObjectSharingListDeleteMutation.graphql';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';

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
  inContainer?: boolean
  disabled?: boolean
}

const StixCoreObjectSharingList = ({ data, disabled, inContainer }: StixCoreObjectSharingListProps) => {
  const draftContext = useDraftContext();
  const { t_i18n } = useFormatter();
  const disabledInDraft = !!draftContext;
  const fullyDisabled = disabled || disabledInDraft;
  const notifySuccessMessage = (<span>
    {t_i18n(
      'The background task has been executed. You can monitor it on',
    )}{' '}
    {<Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link>}
    .
  </span>);
  const [deleteOrganization] = useApiMutation<StixCoreObjectSharingListDeleteMutation>(
    objectOrganizationDeleteMutation,
    undefined,
    inContainer ? { successMessage: notifySuccessMessage } : undefined,
  );
  const [disabledOrgs, setDisabledOrgs] = useState<string[]>([]);
  const { objectOrganization, id } = useFragment(objectOrganizationFragment, data);
  if (objectOrganization?.length === 0) return null;

  const removeOrganization = (organizationId: string) => {
    if (inContainer) {
      const newDisabledOrgs = [...disabledOrgs, organizationId];
      setDisabledOrgs(newDisabledOrgs);
    }
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
            disabled={fullyDisabled || disabledOrgs.includes(organization.id)}
          />
        </Tooltip>
      ))}
    </div>
  );
};

export default StixCoreObjectSharingList;
