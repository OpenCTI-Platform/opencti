import React from 'react';
import IngestionMenu from './IngestionMenu';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import WorkersStatus, { workersStatusQuery } from './connectors/WorkersStatus';
import ConnectorsStatus, { connectorsStatusQuery } from './connectors/ConnectorsStatus';
import Loader, { LoaderVariant } from '../../../components/Loader';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import useHelper from '../../../utils/hooks/useHelper';

const Connectors = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { isFeatureEnable } = useHelper();
  const enableComposerFeatureFlag = isFeatureEnable('COMPOSER');
  setTitle(t_i18n('Connectors | Ingestion | Data'));
  return (
    <>
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs
          variant="list"
          elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Connectors'), current: true }]}
          noMargin
        />
        <QueryRenderer
          query={workersStatusQuery}
          render={({ props }) => {
            if (props) {
              return <WorkersStatus data={props} />;
            }
            return <Loader variant={LoaderVariant.container} />;
          }}
        />
        <QueryRenderer
          query={connectorsStatusQuery}
          variables={{ enableComposerFeatureFlag }}
          render={({ props }) => {
            if (props) {
              return <ConnectorsStatus data={props} />;
            }
            return <Loader variant={LoaderVariant.container} />;
          }}
        />
      </PageContainer>
    </>
  );
};

export default Connectors;
