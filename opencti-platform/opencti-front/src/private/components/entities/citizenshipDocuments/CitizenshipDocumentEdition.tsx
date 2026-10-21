import { graphql, commitMutation } from 'react-relay';
import React, { FunctionComponent } from 'react';
import CitizenshipDocumentEditionContainer from '@components/entities/citizenshipDocuments/CitizenshipDocumentEditionContainer';
import { citizenshipDocumentEditionOverviewFocus } from '@components/entities/citizenshipDocuments/CitizenshipDocumentEditionOverview';
import { CitizenshipDocumentEditionContainerQuery$data } from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentEditionContainerQuery.graphql';
import { environment, QueryRenderer } from '../../../../relay/environment';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';

export const citizenshipDocumentEditionQuery = graphql`
query CitizenshipDocumentEditionContainerQuery($id: String!) {
    citizenshipDocument(id: $id) {
        ...CitizenshipDocumentEditionContainer_citizenshipDocument
    }
}
`;

interface CitizenshipDocumentEditionProps {
  citizenshipDocumentId: string;
}

const CitizenshipDocumentEdition: FunctionComponent<CitizenshipDocumentEditionProps> = ({
  citizenshipDocumentId,
}) => {
  const handleClose = () => {
    commitMutation(environment, {
      mutation: citizenshipDocumentEditionOverviewFocus,
      variables: {
        id: citizenshipDocumentId,
        input: { focusOn: '' },
      },
    });
  };

  return (
    <QueryRenderer
      query={citizenshipDocumentEditionQuery}
      variables={{ id: citizenshipDocumentId }}
      render={({ props }: { props: CitizenshipDocumentEditionContainerQuery$data }) => {
        if (props && props.citizenshipDocument) {
          return (
            <CitizenshipDocumentEditionContainer
              citizenshipDocument={props.citizenshipDocument}
              handleClose={handleClose}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant={LoaderVariant.inline} />;
      }}
    />
  );
};

export default CitizenshipDocumentEdition;
