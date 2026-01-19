export const getStrategyConfigEnum = (selectedStrategy: string | null) => {
  switch (selectedStrategy) {
    case 'SAML': return 'SamlStrategy';
    case 'OpenID': return 'OpenIDConnectStrategy';
    case 'Header': return 'HeaderStrategy';
    case 'ClientCert': return 'ClientCertStrategy';
    case 'LDAP': return 'LdapStrategy';
    case 'LocalAuth': return 'LocalStrategy';
    default: return null;
  }
};

export const getStrategyConfigSelected = (selectedStrategy: string | null) => {
  switch (selectedStrategy) {
    case 'SamlStrategy': return 'SAML';
    case 'OpenIDConnectStrategy': return 'OpenID';
    case 'HeaderStrategy': return 'Header';
    case 'ClientCertStrategy': return 'ClientCert';
    case 'LdapStrategy': return 'LDAP';
    case 'LocalStrategy': return 'LocalAuth';
    default: return null;
  }
};
