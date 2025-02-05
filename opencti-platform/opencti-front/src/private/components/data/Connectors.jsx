import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import IngestionMenu from './IngestionMenu';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import WorkersStatus, { workersStatusQuery } from './connectors/WorkersStatus';
import ConnectorsStatus, { connectorsStatusQuery } from './connectors/ConnectorsStatus';
import Loader, { LoaderVariant } from '../../../components/Loader';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Connectors = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Ingestion: Connectors | Data'));
  return (
    <div className={classes.container}>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Connectors'), current: true }]} />
      <IngestionMenu/>
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
        render={({ props }) => {
          if (props) {
            return <ConnectorsStatus data={props} />;
          }
          return <Loader variant={LoaderVariant.container} />;
        }}
      />
    </div>
  );
};

export default Connectors;
