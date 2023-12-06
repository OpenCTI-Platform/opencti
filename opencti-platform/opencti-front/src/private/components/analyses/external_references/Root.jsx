import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql } from 'react-relay';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import ExternalReference from './ExternalReference';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import withRouter from '../../../../utils/compat-router/withRouter';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

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
      params: { externalReferenceId },
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
      params: { externalReferenceId },
    } = this.props;
    return (
      <div>
        <QueryRenderer
          query={externalReferenceQuery}
          variables={{ id: externalReferenceId }}
          render={({ props }) => {
            if (props) {
              if (props.externalReference && props.connectorsForImport) {
                return (
                  <RelateComponentContextProvider>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <ExternalReference
                            externalReference={props.externalReference}
                            connectorsImport={props.connectorsForImport}
                          />}
                      />
                    </Routes>
                  </RelateComponentContextProvider>
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
};

export default withRouter(RootExternalReference);
