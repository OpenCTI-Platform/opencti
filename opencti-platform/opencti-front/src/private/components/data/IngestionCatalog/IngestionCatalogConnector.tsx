import { useParams } from 'react-router-dom';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ingestionCatalogQuery } from '@components/data/IngestionCatalog';
import { IngestionCatalogQuery } from '@components/data/__generated__/IngestionCatalogQuery.graphql';
import React from 'react';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import { VerifiedOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import Paper from '@mui/material/Paper';
import { Git, Launch } from 'mdi-material-ui';
import Button from '@mui/material/Button';
import type { Theme } from '../../../../components/Theme';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { truncate } from '../../../../utils/String';

interface IngestionCatalogConnectorComponentProps {
  queryRef: PreloadedQuery<IngestionCatalogQuery>;
}

const IngestionCatalogConnectorComponent = ({
  queryRef,
}: IngestionCatalogConnectorComponentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Catalog | Ingestion | Data'));
  const { connectorId } = useParams();

  const { catalogs } = usePreloadedQuery(
    ingestionCatalogQuery,
    queryRef,
  );

  const findContractByName = () => {
    for (const catalog of catalogs) {
      for (const contractStr of catalog.contracts || []) {
        const contract = JSON.parse(contractStr);
        if (contract.default.CONNECTOR_NAME === connectorId) {
          return contract;
        }
      }
    }
    return null;
  };

  const connector = findContractByName();
  const connectorName = connector.default.CONNECTOR_NAME;

  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Catalog') }, { label: connectorName, current: true }]} />
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: theme.spacing(2) }}>
        <div style={{ display: 'flex', gap: 20 }}>
          <img
            style={{ height: 37, maxWidth: 100, borderRadius: 4 }}
            src={connector.logo}
            alt={connector.title}
          />
          <div>
            <div style={{ display: 'flex', flex: 1, alignItems: 'center', gap: 20 }}>
              <Typography
                variant="h1"
                style={{
                  textTransform: 'uppercase',
                  marginBottom: 0,
                }}
              >
                {connector.title}
              </Typography>
              <Chip
                style={{
                  textTransform: 'uppercase',
                  borderRadius: 4,
                }}
                icon={<VerifiedOutlined color="success" />}
                label={
                  <Typography color={'success'}>
                    {t_i18n('Verified')}
                  </Typography>
                }
              />
            </div>
            <div style={{ display: 'flex', flex: 1, alignItems: 'center' }}>
              {connector.use_cases.map((useCase: string) => (
                <Chip
                  key={useCase}
                  variant="outlined"
                  size="small"
                  style={{
                    margin: '7px 7px 7px 0',
                    borderRadius: 4,
                  }}
                  label={truncate(useCase, 25)}
                />
              ))}
            </div>
          </div>
        </div>
        <div>
          <Button variant="contained" disabled>{t_i18n('Deploy')}</Button>
          <Button
            variant="contained"
            startIcon={<Launch />}
            style={{
              marginLeft: theme.spacing(2),
            }}
            href={connector.subscription_link}
            target="blank"
            rel="noopener noreferrer"
          >
            {t_i18n('', { id: 'Test ... with OpenCTI', values: { connectorName } })}
          </Button>
        </div>
      </div>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={8}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Overview')}
          </Typography>
          <Paper
            style={{
              marginTop: theme.spacing(1),
              padding: '15px',
              borderRadius: 4,
            }}
            variant="outlined"
          >
            {connector.description}
          </Paper>
        </Grid>
        <Grid item xs={4}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Basic information')}
          </Typography>
          <Paper
            style={{
              marginTop: theme.spacing(1),
              padding: '15px',
              borderRadius: 4,
            }}
            variant="outlined"
          >
            <Grid item xs={12}>
              <Button size="large" startIcon={<Git />} href={connector.source_code} target="blank" rel="noopener noreferrer">
                {connector.title}
              </Button>
            </Grid>
            <Grid item xs={12}>
              <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
                {t_i18n('Last update')}
              </Typography>
              {connector.last_verified_date}
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </>
  );
};

const IngestionCatalogConnector = () => {
  const queryRef = useQueryLoading<IngestionCatalogQuery>(
    ingestionCatalogQuery,
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <IngestionCatalogConnectorComponent
        queryRef={queryRef}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default IngestionCatalogConnector;
