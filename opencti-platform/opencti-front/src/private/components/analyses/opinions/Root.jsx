import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql } from 'react-relay';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Opinion from './Opinion';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import withRouter from '../../../../utils/compat-router/withRouter';

const subscription = graphql`
  subscription RootOpinionSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Opinion {
        ...Opinion_opinion
        ...OpinionEditionContainer_opinion
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const opinionQuery = graphql`
  query RootOpinionQuery($id: String!) {
    opinion(id: $id) {
      standard_id
      entity_type
      ...Opinion_opinion
      ...OpinionDetails_opinion
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixObjectsOrStixRelationships_container
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

class RootOpinion extends Component {
  constructor(props) {
    super(props);
    const {
      params: { opinionId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: opinionId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      params: { opinionId },
    } = this.props;
    return (
      <>
        <QueryRenderer
          query={opinionQuery}
          variables={{ id: opinionId }}
          render={({ props }) => {
            if (props) {
              if (props.opinion) {
                return (
                  <Routes>
                    <Route
                      path="/"
                      element={(
                        <Opinion opinion={props.opinion} enableReferences={false} />
                      )}
                    />
                    <Route
                      path="/knowledge/relations/:relationId"
                      element={
                        <StixCoreRelationship
                          entityId={props.opinion.id}
                        />
                      }
                    />
                  </Routes>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootOpinion.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default withRouter(RootOpinion);
