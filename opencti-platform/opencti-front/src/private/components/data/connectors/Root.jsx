import React from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, useParams } from 'react-router-dom';
import { QueryRenderer } from '../../../../relay/environment';
import Connector, { connectorQuery } from './Connector';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';

const RootConnector = () => {
  const { t_i18n } = useFormatter();
  const { connectorId } = useParams();
  return (
    <QueryRenderer
      query={connectorQuery}
      variables={{ id: connectorId }}
      render={({ props }) => {
        if (props) {
          if (props.connector) {
            return (
              <>
                <Breadcrumbs elements={[{ label: t_i18n('Integrations') }, { label: t_i18n('Deployed'), link: '/dashboard/integrations/deployed' }, { label: props.connector.title, current: true }]} />
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
};

RootConnector.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default RootConnector;
