import { Badge, Tooltip } from '@mui/material';
import Button from '@common/button/Button';
import React from 'react';
import { useFormatter } from '../../../../../../components/i18n';

type IngestionCatalogCardDeployButtonProps = {
  deploymentCount?: number;
  onClick: () => void;
};

const IngestionCatalogCardDeployButton = ({ deploymentCount, onClick }: IngestionCatalogCardDeployButtonProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Tooltip title={deploymentCount ? `${deploymentCount} deployments` : ''}>
      <Badge badgeContent={deploymentCount} color="warning">
        <Button
          onClick={onClick}
        >
          {t_i18n('Deploy')}
        </Button>
      </Badge>
    </Tooltip>
  );
};

export default IngestionCatalogCardDeployButton;
