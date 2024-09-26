import React from 'react';
import { graphql } from 'react-relay';
import OpinionEditionContainer from './OpinionEditionContainer';
import { QueryRenderer } from '../../../../relay/environment';
import { opinionEditionOverviewFocus } from './OpinionEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { CollaborativeSecurity } from '../../../../utils/Security';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const opinionEditionQuery = graphql`
  query OpinionEditionContainerQuery($id: String!) {
    opinion(id: $id) {
      createdBy {
        id
      }
      ...OpinionEditionContainer_opinion
    }
  }
`;

const OpinionEdition = ({ opinionId }) => {
  const [commit] = useApiMutation(opinionEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: opinionId,
        input: { focusOn: '' },
      },
    });
  };

  return (
    <div>
      <QueryRenderer
        query={opinionEditionQuery}
        variables={{ id: opinionId }}
        render={({ props }) => {
          if (props) {
            return (
              <CollaborativeSecurity
                data={props.opinion}
                needs={[KNOWLEDGE_KNUPDATE]}
              >
                <OpinionEditionContainer
                  opinion={props.opinion}
                  handleClose={handleClose}
                />
              </CollaborativeSecurity>
            );
          }
          return <Loader variant={LoaderVariant.inline} />;
        }}
      />
    </div>
  );
};

export default OpinionEdition;
