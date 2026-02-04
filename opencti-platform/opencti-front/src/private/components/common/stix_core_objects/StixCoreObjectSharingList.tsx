import { ReactNode, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { StixCoreObjectSharingListDeleteMutation } from './__generated__/StixCoreObjectSharingListDeleteMutation.graphql';
import { StixCoreObjectSharingListFragment$key } from './__generated__/StixCoreObjectSharingListFragment.graphql';
import Tag from '@common/tag/Tag';
import { AccountBalanceOutlined } from '@mui/icons-material';
import TagsOverflow from '@common/tag/TagsOverflow';

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
  const draftContext = useDraftContext();
  const { t_i18n } = useFormatter();
  const disabledInDraft = !!draftContext;
  const fullyDisabled = disabled || disabledInDraft;
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
        <Tag
          label={organization.name}
          onDelete={() => removeOrganization(organization.id)}
          disabled={fullyDisabled || disabledOrgs.includes(organization.id)}
          icon={<AccountBalanceOutlined fontSize="small" />}
          maxWidth={150}
        />
      )}
      direction="rtl"
    >
      {children}
    </TagsOverflow>
  );
};

export default StixCoreObjectSharingList;
