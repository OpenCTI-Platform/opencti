import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import ExternalReference from './ExternalReference';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootExternalReferenceSubscription($id: ID!) {
    externalReference(id: $id) {
      ...ExternalReference_externalReference
    }
  }
`;

const externalReferenceQuery = graphql`
  query RootExternalReferenceQuery($id: String!) {
    externalReference(id: $id) {
      standard_id
      ...ExternalReference_externalReference
    }
    connectorsForImport {
      ...ExternalReference_connectorsImport
    }
  }
`;

class RootExternalReference extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { externalReferenceId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: externalReferenceId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { externalReferenceId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={externalReferenceQuery}
          variables={{ id: externalReferenceId }}
          render={({ props }) => {
            if (props) {
              if (props.externalReference && props.connectorsForImport) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/analysis/external_references/:externalReferenceId"
                      render={(routeProps) => (
                        <ExternalReference
                          {...routeProps}
                          externalReference={props.externalReference}
                          connectorsImport={props.connectorsForImport}
                        />
                      )}
                    />
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootExternalReference.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootExternalReference);
