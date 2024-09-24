import React, { useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import ExternalReference from './ExternalReference';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Breadcrumbs from '../../../../components/Breadcrumbs';

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

const RootExternalReference = () => {
  const { externalReferenceId } = useParams();
  const subConfig = useMemo(
    () => ({
      subscription,
      variables: { id: externalReferenceId },
    }),
    [externalReferenceId],
  );

  const { t_i18n } = useFormatter();
  useSubscription(subConfig);

  return (
    <div>
      <QueryRenderer
        query={externalReferenceQuery}
        variables={{ id: externalReferenceId }}
        render={({ props }) => {
          if (props) {
            if (props.externalReference && props.connectorsForImport) {
              return (
                <>
                  <Breadcrumbs elements={[
                    { label: t_i18n('Analyses') },
                    { label: t_i18n('External references'), link: '/dashboard/analyses/external_references' },
                  ]}
                  />
                  <ExternalReference
                    externalReference={props.externalReference}
                    connectorsImport={props.connectorsForImport}
                  />
                </>
              );
            }
            return <ErrorNotFound/>;
          }
          return <Loader/>;
        }}
      />
    </div>
  );
};

export default RootExternalReference;
