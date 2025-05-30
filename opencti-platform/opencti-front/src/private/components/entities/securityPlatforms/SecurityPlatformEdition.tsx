import { graphql, QueryRenderer, commitMutation } from 'react-relay';
import React, { FunctionComponent } from 'react';
import SecurityPlatformEditionContainer from '@components/entities/securityPlatforms/SecurityPlatformEditionContainer';
import { securityPlatformEditionOverviewFocus } from '@components/entities/securityPlatforms/SecurityPlatformEditionOverview';
import { environment } from '../../../../relay/environment';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader from '../../../../components/Loader';

export const securityPlatformEditionQuery = graphql`
query SecurityPlatformEditionContainerQuery($id: String!) {
    securityPlatform(id: $id) {
        ...SecurityPlatformEditionContainer_securityPlatform
    }
}
`;

interface SecurityPlatformEditionProps {
  securityPlatformId: string
}

const SecurityPlatformEdition : FunctionComponent<SecurityPlatformEditionProps> = ({
  securityPlatformId,
}) => {
  const handleClose = () => {
    commitMutation(environment, {
      mutation: securityPlatformEditionOverviewFocus,
      variables: {
        id: securityPlatformId,
        input: { focusOn: '' },
      },
    });
  };

  return (
    <QueryRenderer
      environment={environment}
      query={securityPlatformEditionQuery}
      variables={{ id: securityPlatformId }}
      render={({ props }) => {
        if (props) {
          return (
            <SecurityPlatformEditionContainer
              securityPlatform={props.securityPlatform}
              handleClose={ handleClose}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant="inline" />;
      }}
    />
  );
};

export default SecurityPlatformEdition;
