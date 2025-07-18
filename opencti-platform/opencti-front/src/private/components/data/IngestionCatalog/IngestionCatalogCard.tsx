import Card from '@mui/material/Card';
import React from 'react';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';

const styles = {
  card: {
    width: '100%',
    height: 330,
    borderRadius: 4,
  },
  header: {
    height: 55,
    paddingBottom: 0,
    marginBottom: 0,
  },
  description: {
    marginTop: 5,
    height: 65,
    display: '-webkit-box',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    '-webkit-line-clamp': 3,
    '-webkit-box-orient': 'vertical',
  }
};

interface IngestionCatalogCardProps {
  contract: string;
}

const IngestionCatalogCard = ({ contract }: IngestionCatalogCardProps) => {
  const connector = JSON.parse(contract);
  return (
    <>
      <Card
        style={styles.card}
        variant="outlined"
      >
        <CardHeader
          style={styles.header}
          // classes={{ title: classes.title }}
          avatar={
            <img
              style={{ height: 37, maxWidth: 100, borderRadius: 4 }}
              src={connector.logo}
              alt={connector.title}
            />
          }
          title={connector.title}
        />
        <CardContent style={{
          width: '100%',
          paddingTop: 0,
        }}>
          <div style={styles.description}>
            {connector.description}
          </div>
        </CardContent>
      </Card>
    </>
  );
};

export default IngestionCatalogCard;