import { Badge, Tooltip } from '@mui/material';
import Button from '@mui/material/Button';
import React from 'react';
import { useFormatter } from '../../../../../../components/i18n';

const IngestionCatalogCardDeployButton = ({ deploymentCount, onClick }: { deploymentCount?: number, onClick: () => void }) => {
  const { t_i18n } = useFormatter();

  return (
    <Tooltip title={deploymentCount ? `${deploymentCount} deployments` : '' }>
      <Badge badgeContent={deploymentCount} color={'warning'}>
        <Button
          variant="contained"
          onClick={onClick}
          size="small"
        >
          {t_i18n('Deploy')}
        </Button>
      </Badge>
    </Tooltip>
  );
};

export default IngestionCatalogCardDeployButton;
