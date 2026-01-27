export const getStrategyConfigEnum = (selectedStrategy: string | null) => {
  switch (selectedStrategy) {
    case 'SAML': return 'SamlStrategy';
    case 'OpenID': return 'OpenIDConnectStrategy';
    case 'LDAP': return 'LdapStrategy';
    case 'Header': return 'HeaderStrategy';
    case 'ClientCert': return 'ClientCertStrategy';
    case 'LocalAuth': return 'LocalStrategy';
    default: return null;
  }
};

export const getStrategyConfigSelected = (selectedStrategy: string | null) => {
  switch (selectedStrategy) {
    case 'SamlStrategy': return 'SAML';
    case 'OpenIDConnectStrategy': return 'OpenID';
    case 'LdapStrategy': return 'LDAP';
    case 'HeaderStrategy': return 'Header';
    case 'ClientCertStrategy': return 'ClientCert';
    case 'LocalStrategy': return 'LocalAuth';
    default: return null;
  }
};
