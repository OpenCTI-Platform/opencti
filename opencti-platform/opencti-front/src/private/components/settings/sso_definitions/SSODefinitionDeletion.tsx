import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import React, { ReactNode, UIEvent } from 'react';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../utils/domEvent';
import DeleteDialog from '../../../../components/DeleteDialog';
import { deleteNode } from '../../../../utils/store';
import { SSODefinitionDeletionOidcMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionDeletionOidcMutation.graphql';
import { SSODefinitionDeletionSamlMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionDeletionSamlMutation.graphql';
import { SSODefinitionDeletionLdapMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionDeletionLdapMutation.graphql';

const oidcDeletionMutation = graphql`
    mutation SSODefinitionDeletionOidcMutation($id: ID!) {
        oidcProviderDelete(id: $id)
    }
`;

const samlDeletionMutation = graphql`
    mutation SSODefinitionDeletionSamlMutation($id: ID!) {
        samlProviderDelete(id: $id)
    }
`;

const ldapDeletionMutation = graphql`
    mutation SSODefinitionDeletionLdapMutation($id: ID!) {
        ldapProviderDelete(id: $id)
    }
`;

interface ChildrenProps {
  handleOpenDelete: (e?: UIEvent) => void;
  deleting: boolean;
}

interface SSODefinitionDeletionProps {
  ssoId: string;
  providerType: string;
  paginationOptions?: Record<string, unknown>;
  onDeleteComplete?: () => void;
  children: (props: ChildrenProps) => ReactNode;
}

const SSODefinitionDeletion = ({ ssoId, providerType, paginationOptions, onDeleteComplete, children }: SSODefinitionDeletionProps) => {
  const { t_i18n } = useFormatter();

  const getMutationForType = () => {
    switch (providerType) {
      case 'OIDC': return oidcDeletionMutation;
      case 'SAML': return samlDeletionMutation;
      case 'LDAP': return ldapDeletionMutation;
      default: return oidcDeletionMutation;
    }
  };

  const [deleteMutation, deleting] = useApiMutation<
    SSODefinitionDeletionOidcMutation | SSODefinitionDeletionSamlMutation | SSODefinitionDeletionLdapMutation
  >(
    getMutationForType(),
    undefined,
    { successMessage: `${t_i18n('Authentication')} ${t_i18n('successfully deleted')}` },
  );

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    deleteMutation({
      variables: { id: ssoId },
      updater: (store: RecordSourceSelectorProxy) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_authenticationProviders', paginationOptions, ssoId);
        }
      },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      {children({ handleOpenDelete, deleting })}
      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this Authentication?')}
      />
    </>
  );
};

export default SSODefinitionDeletion;
