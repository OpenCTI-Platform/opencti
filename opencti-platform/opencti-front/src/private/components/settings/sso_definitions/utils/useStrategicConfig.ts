export const getStrategyConfigEnum = (selectedStrategy: string | null) => {
  return selectedStrategy === 'SAML' ? 'SamlStrategy'
    : selectedStrategy === 'OpenID' ? 'OpenIDConnectStrategy'
      : selectedStrategy === 'Header' ? 'HeaderStrategy'
        : selectedStrategy === 'ClientCert' ? 'ClientCertStrategy'
          : selectedStrategy === 'Ldap' ? 'LdapStrategy'
            : selectedStrategy === 'LocalAuth' ? 'LocalStrategy' : null;
};

export const getStrategyConfigSelected = (selectedStrategy: string | null) => {
  return selectedStrategy === 'SamlStrategy' ? 'SAML'
    : selectedStrategy === 'OpenIDConnectStrategy' ? 'OpenID'
      : selectedStrategy === 'HeaderStrategy' ? 'Header'
        : selectedStrategy === 'ClientCertStrategy' ? 'ClientCert'
          : selectedStrategy === 'LdapStrategy' ? 'Ldap'
            : selectedStrategy === 'LocalStrategy' ? 'LocalAuth' : null;
};
