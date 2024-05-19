import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import EditEntityControlledDial from 'src/components/EditEntityButton';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ExternalReferenceEditionContainer from './ExternalReferenceEditionContainer';
import { externalReferenceEditionOverviewFocus } from './ExternalReferenceEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { ExternalReferenceEditionContainerQuery$data } from './__generated__/ExternalReferenceEditionContainerQuery.graphql';

export const externalReferenceEditionQuery = graphql`
  query ExternalReferenceEditionContainerQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceEditionContainer_externalReference
    }
  }
`;

interface ExternalReferenceEditionProps {
  externalReferenceId: string;
}

const ExternalReferenceEdition: FunctionComponent<
ExternalReferenceEditionProps
> = ({ externalReferenceId }) => {
  const handleClose = () => {
    commitMutation({
      mutation: externalReferenceEditionOverviewFocus,
      variables: {
        id: externalReferenceId,
        input: { focusOn: '' },
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <QueryRenderer
      query={externalReferenceEditionQuery}
      variables={{ id: externalReferenceId }}
      render={({
        props,
      }: {
        props: ExternalReferenceEditionContainerQuery$data;
      }) => {
        if (props && props.externalReference) {
          return (
            <ExternalReferenceEditionContainer
              externalReference={props.externalReference}
              handleClose={handleClose}
              controlledDial={EditEntityControlledDial()}
            />
          );
        }
        return <Loader variant={LoaderVariant.inElement} />;
      }}
    />
  );
};

export default ExternalReferenceEdition;
