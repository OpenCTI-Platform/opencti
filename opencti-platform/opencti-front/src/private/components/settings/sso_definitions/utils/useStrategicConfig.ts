export const getStrategyConfigEnum = (selectedStrategy: string) => {
  switch (selectedStrategy) {
    case 'SAML': return 'SamlStrategy';
    case 'OpenID': return 'OpenIDConnectStrategy';
    case 'LDAP': return 'LdapStrategy';
    case 'Header': return 'HeaderStrategy';
    case 'ClientCert': return 'ClientCertStrategy';
    case 'LocalAuth': return 'LocalStrategy';
    default: return '';
  }
};

export const getStrategyConfigSelected = (selectedStrategy: string) => {
  switch (selectedStrategy) {
    case 'SamlStrategy': return 'SAML';
    case 'OpenIDConnectStrategy': return 'OpenID';
    case 'LdapStrategy': return 'LDAP';
    case 'HeaderStrategy': return 'Header';
    case 'ClientCertStrategy': return 'ClientCert';
    case 'LocalStrategy': return 'LocalAuth';
    default: return '';
  }
};
