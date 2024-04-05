import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, Routes } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import Connector, { connectorQuery } from './Connector';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import inject18n from '../../../../components/i18n';
import withRouter from '../../../../utils/compat-router/withRouter';

class RootConnector extends Component {
  render() {
    const {
      t,
      params: { connectorId },
    } = this.props;
    return (
      <QueryRenderer
        query={connectorQuery}
        variables={{ id: connectorId }}
        render={({ props }) => {
          if (props) {
            if (props.connector) {
              return (
                <>
                  <Breadcrumbs variant="list" elements={[{ label: t('Data') }, { label: t('Ingestion') }, { label: t('Connectors'), link: '/dashboard/data/ingestion/connectors' }, { label: props.connector.name, current: true }]} />
                  <Routes>
                    <Route
                      path="/"
                      element={
                        <Connector connector={props.connector} />
                      }
                    />
                  </Routes>
                </>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    );
  }
}

RootConnector.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default compose(inject18n, withRouter)(RootConnector);
