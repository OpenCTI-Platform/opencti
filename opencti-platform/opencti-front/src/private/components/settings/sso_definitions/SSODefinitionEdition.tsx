import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SSODefinitionDeletion from '@components/settings/sso_definitions/SSODefinitionDeletion';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import IconButton from '@mui/material/IconButton';
import DeleteOutlined from '@mui/icons-material/DeleteOutlined';
import OidcProviderForm from './OidcProviderForm';
import SamlProviderForm from './SamlProviderForm';
import LdapProviderForm from './LdapProviderForm';

export const ssoDefinitionEditionFragment = graphql`
    fragment SSODefinitionEditionFragment on AuthenticationProvider {
        id
        entity_type
        name
        description
        enabled
        button_label_override
        identifier_override
        type
        authLogHistory {
            timestamp
            level
            message
            type
            identifier
            meta
        }
        configuration {
            ... on OidcConfiguration {
                issuer
                client_id
                scopes
                audience
                callback_url
                logout_remote
                logout_callback_url
                use_proxy
                user_info_mapping {
                    email_expr
                    name_expr
                    firstname_expr
                    lastname_expr
                }
                groups_mapping {
                    default_groups
                    groups_expr
                    group_splitter
                    groups_mapping {
                        provider
                        platform
                    }
                    auto_create_groups
                    prevent_default_groups
                }
                organizations_mapping {
                    default_organizations
                    organizations_expr
                    organizations_splitter
                    organizations_mapping {
                        provider
                        platform
                    }
                    auto_create_organizations
                }
                extra_conf {
                    type
                    key
                    value
                }
            }
            ... on SamlConfiguration {
                issuer
                entry_point
                idp_certificate
                callback_url
                logout_remote
                want_assertions_signed
                want_authn_response_signed
                signing_cert
                sso_binding_type
                force_reauthentication
                identifier_format
                signature_algorithm
                digest_algorithm
                authn_context
                disable_requested_authn_context
                disable_request_acs_url
                skip_request_compression
                decryption_cert
                user_info_mapping {
                    email_expr
                    name_expr
                    firstname_expr
                    lastname_expr
                }
                groups_mapping {
                    default_groups
                    groups_expr
                    group_splitter
                    groups_mapping {
                        provider
                        platform
                    }
                    auto_create_groups
                    prevent_default_groups
                }
                organizations_mapping {
                    default_organizations
                    organizations_expr
                    organizations_splitter
                    organizations_mapping {
                        provider
                        platform
                    }
                    auto_create_organizations
                }
                extra_conf {
                    type
                    key
                    value
                }
            }
            ... on LdapConfiguration {
                url
                bind_dn
                search_base
                search_filter
                group_base
                group_filter
                allow_self_signed
                search_attributes
                username_field
                password_field
                credentials_lookup
                group_search_attributes
                user_info_mapping {
                    email_expr
                    name_expr
                    firstname_expr
                    lastname_expr
                }
                groups_mapping {
                    default_groups
                    groups_expr
                    group_splitter
                    groups_mapping {
                        provider
                        platform
                    }
                    auto_create_groups
                    prevent_default_groups
                }
                organizations_mapping {
                    default_organizations
                    organizations_expr
                    organizations_splitter
                    organizations_mapping {
                        provider
                        platform
                    }
                    auto_create_organizations
                }
                extra_conf {
                    type
                    key
                    value
                }
            }
        }
    }
`;

interface SSODefinitionEditionProps {
  isOpen: boolean;
  onClose: () => void;
  data: SSODefinitionEditionFragment$key;
  paginationOptions?: Record<string, unknown>;
}

const SSODefinitionEdition = ({
  isOpen,
  onClose,
  data,
  paginationOptions,
}: SSODefinitionEditionProps) => {
  const { t_i18n } = useFormatter();
  const provider = useFragment(ssoDefinitionEditionFragment, data);

  const renderForm = () => {
    switch (provider.type) {
      case 'OIDC':
        return (
          <OidcProviderForm
            data={provider}
            onCancel={onClose}
            onCompleted={onClose}
          />
        );
      case 'SAML':
        return (
          <SamlProviderForm
            data={provider}
            onCancel={onClose}
            onCompleted={onClose}
          />
        );
      case 'LDAP':
        return (
          <LdapProviderForm
            data={provider}
            onCancel={onClose}
            onCompleted={onClose}
          />
        );
      default:
        return (
          <div style={{ padding: 20 }}>
            {t_i18n('Unknown provider type')}: {provider.type}
          </div>
        );
    }
  };

  return (
    <Drawer
      title={t_i18n(`Update ${provider.type} Authentication`)}
      open={isOpen}
      onClose={onClose}
      disableBackdropClose
      header={(
        <SSODefinitionDeletion
          ssoId={provider.id}
          providerType={provider.type}
          paginationOptions={paginationOptions}
          onDeleteComplete={onClose}
        >
          {({ handleOpenDelete, deleting }) => (
            <IconButton
              onClick={handleOpenDelete}
              disabled={deleting}
              color="error"
              size="small"
              aria-label={t_i18n('Delete')}
            >
              <DeleteOutlined fontSize="small" />
            </IconButton>
          )}
        </SSODefinitionDeletion>
      )}
    >
      {renderForm()}
    </Drawer>
  );
};

export default SSODefinitionEdition;
