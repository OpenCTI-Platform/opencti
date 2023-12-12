import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Opinion from './Opinion';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';

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
      match: {
        params: { opinionId },
      },
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
      match: {
        params: { opinionId },
      },
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
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/analyses/opinions/:opinionId"
                      render={(routeProps) => (
                        <Opinion {...routeProps} opinion={props.opinion} />
                      )}
                    />
                  </Switch>
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
  match: PropTypes.object,
};

export default withRouter(RootOpinion);
