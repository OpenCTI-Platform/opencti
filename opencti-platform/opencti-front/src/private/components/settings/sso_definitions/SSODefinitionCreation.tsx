import React, { FunctionComponent, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { PaginationOptions } from '../../../../components/list_lines';
import CreateSplitControlledDial from '../../../../components/CreateSplitControlledDial';
import OidcProviderForm from './OidcProviderForm';
import SamlProviderForm from './SamlProviderForm';
import LdapProviderForm from './LdapProviderForm';

interface SSODefinitionCreationProps {
  paginationOptions: PaginationOptions;
}

const SSODefinitionCreation: FunctionComponent<SSODefinitionCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [selectedStrategy, setSelectedStrategy] = useState<string>('');

  const CreateSSODefinitionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateSplitControlledDial
      entityType="SSODefinition"
      options={['Create OIDC', 'Create SAML', 'Create LDAP']}
      onOptionClick={(option) => {
        switch (option) {
          case 'Create OIDC': {
            setSelectedStrategy('OIDC');
            break;
          }
          case 'Create SAML': {
            setSelectedStrategy('SAML');
            break;
          }
          case 'Create LDAP': {
            setSelectedStrategy('LDAP');
            break;
          }
          default: setSelectedStrategy('');
        }
      }}
      {...props}
    />
  );

  const getTitle = () => {
    switch (selectedStrategy) {
      case 'OIDC': return t_i18n('Create OIDC Authentication');
      case 'SAML': return t_i18n('Create SAML Authentication');
      case 'LDAP': return t_i18n('Create LDAP Authentication');
      default: return t_i18n('Create Authentication');
    }
  };

  return (
    <Drawer
      title={getTitle()}
      controlledDial={CreateSSODefinitionControlledDial}
    >
      {({ onClose }) => {
        const handleCompleted = () => {
          onClose();
          setSelectedStrategy('');
        };
        const handleCancel = () => {
          onClose();
          setSelectedStrategy('');
        };
        switch (selectedStrategy) {
          case 'OIDC':
            return (
              <OidcProviderForm
                onCancel={handleCancel}
                onCompleted={handleCompleted}
                paginationOptions={paginationOptions}
              />
            );
          case 'SAML':
            return (
              <SamlProviderForm
                onCancel={handleCancel}
                onCompleted={handleCompleted}
                paginationOptions={paginationOptions}
              />
            );
          case 'LDAP':
            return (
              <LdapProviderForm
                onCancel={handleCancel}
                onCompleted={handleCompleted}
                paginationOptions={paginationOptions}
              />
            );
          default:
            return null;
        }
      }}
    </Drawer>
  );
};

export default SSODefinitionCreation;
