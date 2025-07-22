import Card from '@mui/material/Card';
import React from 'react';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { CardActions, Grid, Tooltip } from '@mui/material';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { VerifiedOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';

const styles = {
  description: {
    marginTop: 5,
    height: 170,
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 3,
    '-webkit-box-orient': 'vertical',
  },
};

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
        title={(
          <Grid container={true} spacing={3}>
            {connector.use_cases.map((useCase: string) => (
              <Grid key={useCase} item xs={6}>
                <Chip
                  key={useCase}
                  variant="outlined"
                  size="small"
                  style={{
                    margin: '7px 7px 7px 0',
                    borderRadius: 4,
                  }}
                  label={useCase}
                />
              </Grid>
            ))}
          </Grid>
        )}
        style={{ display: 'flex' }}
      >
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
      </Tooltip>
    );
  };

  return (
    <Card
      style={{
        width: '100%',
        height: 330,
        borderRadius: 4,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
      }}
      variant="outlined"
    >
      <CardHeader
        style={{
          height: 100,
          paddingBottom: 0,
          marginBottom: 0,
          alignItems: 'start',
        }}
        avatar={
          <img
            style={{ height: 37, maxWidth: 100, borderRadius: 4 }}
            src={connector.logo}
            alt={connector.title}
          />
        }
        title={
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div style={{ fontSize: 20, fontWeight: 600 }}>{connector.title}</div>
            <VerifiedOutlined color={'success'} />
          </div>
        }
        subheader={renderUseCases()}
      />
      <CardContent style={{
        width: '100%',
        height: '100%',
        paddingTop: 0,
      }}
      >
        <div style={styles.description}>
          {connector.short_description}
        </div>
      </CardContent>
      <CardActions style={{
        alignSelf: 'end',
      }}
      >
        <Button variant={'contained'} size={'small'} onClick={() => navigate(link)}>{t_i18n('Details')}</Button>
        <Button variant={'contained'} size={'small'} disabled>{t_i18n('Deploy')}</Button>
      </CardActions>
    </Card>
  );
};

export default IngestionCatalogCard;
