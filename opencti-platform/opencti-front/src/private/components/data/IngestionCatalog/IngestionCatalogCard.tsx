import Card from '@mui/material/Card';
import React from 'react';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { Badge, CardActions, Grid } from '@mui/material';
import Button from '@mui/material/Button';
import { VerifiedOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import IngestionCatalogUseCaseChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import { useFormatter } from '../../../../components/i18n';
import EnrichedTooltip from '../../../../components/EnrichedTooltip';

interface IngestionCatalogCardProps {
  node: string;
}

export interface IngestionConnector {
  logo: string,
  title: string,
  description: string,
  short_description: string,
  source_code: string,
  last_verified_date: string,
  subscription_link: string,
  verified: boolean,
  use_cases: string[],
  default: {
    CONNECTOR_NAME: string
  }
}

const IngestionCatalogCard = ({ node }: IngestionCatalogCardProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const connector: IngestionConnector = JSON.parse(node);
  const link = `/dashboard/data/ingestion/catalog/${connector.default.CONNECTOR_NAME}`;

  const renderUseCases = () => {
    return (
      <EnrichedTooltip
        title={(
          <Grid container={true} spacing={3}>
            {connector.use_cases.map((useCase: string) => <Grid key={useCase} item xs={6}><IngestionCatalogUseCaseChip useCase={useCase} /></Grid>)}
          </Grid>
        )}
      >
        {connector.use_cases.length > 1 ? (
          <Badge
            variant="dot"
            color="primary"
            sx={{
              '& .MuiBadge-badge': {
                right: 8,
                top: 8,
              },
            }}
          >
            {connector.use_cases.slice(0, 1).map((useCase: string) => <IngestionCatalogUseCaseChip key={useCase} useCase={useCase} />)}
          </Badge>
        ) : (
          <>
            {connector.use_cases.map((useCase: string) => <IngestionCatalogUseCaseChip key={useCase} useCase={useCase} />)}
          </>
        )}
      </EnrichedTooltip>
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
        avatar={<img style={{ height: 50, width: 50, objectFit: 'cover', borderRadius: 4 }} src={connector.logo} alt={connector.title} />}
        title={<div style={{ width: '100%', fontSize: 20, fontWeight: 600 }}>{connector.title}</div>}
        subheader={renderUseCases()}
        action={connector.verified && <VerifiedOutlined color="success" />}
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
