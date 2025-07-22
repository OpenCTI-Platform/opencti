import Card from '@mui/material/Card';
import React from 'react';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { CardActions, Grid, Tooltip } from '@mui/material';
import Button from '@mui/material/Button';
import { VerifiedOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import IngestionCatalogUseCaseChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import { useFormatter } from '../../../../components/i18n';

interface IngestionCatalogCardProps {
  node: string;
}

const IngestionCatalogCard = ({ node }: IngestionCatalogCardProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const connector = JSON.parse(node);
  const link = `/dashboard/data/ingestion/catalog/${connector.default.CONNECTOR_NAME}`;

  const renderUseCases = () => {
    return (
      <Tooltip
        style={{ display: 'flex', width: 200 }}
        title={(
          <Grid container={true} spacing={3}>
            {connector.use_cases.map((useCase: string) => <Grid key={useCase} item xs={6}><IngestionCatalogUseCaseChip useCase={useCase} /></Grid>)}
          </Grid>
        )}
      >
        {connector.use_cases.map((useCase: string) => <IngestionCatalogUseCaseChip key={useCase} useCase={useCase} />)}
      </Tooltip>
    );
  };

  return (
    <Card
      variant="outlined"
      style={{
        height: 330,
        borderRadius: 4,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
      }}
    >

      <CardHeader
        style={{
          height: 100,
          paddingBottom: 0,
          marginBottom: 0,
          alignItems: 'start',
        }}
        avatar={<img style={{ height: 37, maxWidth: 100, borderRadius: 4 }} src={connector.logo} alt={connector.title} />}
        title={<div style={{ width: '100%', fontSize: 20, fontWeight: 600 }}>{connector.title}</div>}
        subheader={renderUseCases()}
        action={<VerifiedOutlined color={'success'} />}
      />

      <CardContent style={{ paddingTop: 0 }}>
        <div style={{ height: 170, overflow: 'hidden', textOverflow: 'ellipsis' }}>{connector.short_description}</div>
      </CardContent>

      <CardActions style={{ alignSelf: 'end' }}>
        <Button variant="contained" size="small" onClick={() => navigate(link)}>{t_i18n('Details')}</Button>
        <Button variant="contained" size="small" disabled>{t_i18n('Deploy')}</Button>
      </CardActions>

    </Card>
  );
};

export default IngestionCatalogCard;
