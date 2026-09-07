import { ReactNode, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import { Stack } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { StixCoreObjectSharingListDeleteMutation } from './__generated__/StixCoreObjectSharingListDeleteMutation.graphql';
import { StixCoreObjectSharingListFragment$key } from './__generated__/StixCoreObjectSharingListFragment.graphql';
import TagsOverflow from '@common/tag/TagsOverflow';
import ItemOrganizations from "src/components/ItemOrganizations";

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
  data: StixCoreObjectSharingListFragment$key;
  inContainer?: boolean;
  disabled?: boolean;
  children?: ReactNode;
}

const StixCoreObjectSharingList = ({ data, disabled, inContainer, children }: StixCoreObjectSharingListProps) => {
  const { t_i18n } = useFormatter();
  const notifySuccessMessage = (
    <span>
      {t_i18n(
        'The background task has been executed. You can monitor it on',
      )}{' '}
      <Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link>
      .
    </span>
  );
  const [deleteOrganization] = useApiMutation<StixCoreObjectSharingListDeleteMutation>(
    objectOrganizationDeleteMutation,
    undefined,
    inContainer ? { successMessage: notifySuccessMessage } : undefined,
  );
  const [disabledOrgs, setDisabledOrgs] = useState<string[]>([]);
  const { objectOrganization, id } = useFragment(objectOrganizationFragment, data);

  const organizations = objectOrganization ?? [];

  if (organizations.length === 0) return null;

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
    <TagsOverflow
      items={objectOrganization || []}
      getKey={(organization) => organization.id}
      getLabel={(organization) => organization.name}
      renderTag={(organization) => (
        <ItemOrganizations
          organizationName={organization.name}
          organizationId={organization.id}
          removeOrganization={removeOrganization}
          disabled={disabled || disabledOrgs.includes(organization.id)}
        />
      )}
      renderOverflowTooltip={(hiddenOrganizations) => (
        <Stack direction="column" gap={0.5} sx={{ p: 0.5 }}>
          {hiddenOrganizations.map((organization) => (
            <ItemOrganizations
              key={organization.id}
              organizationName={organization.name}
              organizationId={organization.id}
              removeOrganization={removeOrganization}
              disabled={disabled || disabledOrgs.includes(organization.id)}
            />
          ))}
        </Stack>
      )}
      direction="rtl"
    >
      {children}
    </TagsOverflow>
  );
};

export default StixCoreObjectSharingList;
