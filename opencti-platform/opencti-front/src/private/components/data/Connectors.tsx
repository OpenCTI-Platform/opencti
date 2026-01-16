import React from 'react';
import IngestionMenu from './IngestionMenu';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import WorkersStatus, { workersStatusQuery } from './connectors/WorkersStatus';
import ConnectorsStatus from './connectors/ConnectorsStatus';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import { WorkersStatusQuery$data } from './__generated__/WorkersStatusQuery.graphql';

const Connectors = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  setTitle(t_i18n('Monitoring | Ingestion | Data'));

  return (
    <div data-testid="connectors-page">
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs
          elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Monitoring'), current: true }]}
          noMargin
        />
        <QueryRenderer
          query={workersStatusQuery}
          render={({ props }: { props: WorkersStatusQuery$data }) => {
            return <WorkersStatus data={props} />;
          }}
        />
        <ConnectorsStatus />
      </PageContainer>
    </div>
  );
};

export default Connectors;
