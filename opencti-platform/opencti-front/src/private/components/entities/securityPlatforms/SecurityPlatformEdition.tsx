import { graphql, commitMutation } from 'react-relay';
import React, { FunctionComponent } from 'react';
import SecurityPlatformEditionContainer from '@components/entities/securityPlatforms/SecurityPlatformEditionContainer';
import { securityPlatformEditionOverviewFocus } from '@components/entities/securityPlatforms/SecurityPlatformEditionOverview';
import { SecurityPlatformEditionContainerQuery$data } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformEditionContainerQuery.graphql';
import { environment, QueryRenderer } from '../../../../relay/environment';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';

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
      query={securityPlatformEditionQuery}
      variables={{ id: securityPlatformId }}
      render={({ props }: { props: SecurityPlatformEditionContainerQuery$data }) => {
        if (props && props.securityPlatform) {
          return (
            <SecurityPlatformEditionContainer
              securityPlatform={props.securityPlatform}
              handleClose={ handleClose}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant={LoaderVariant.inline} />;
      }}
    />
  );
};

export default SecurityPlatformEdition;
