import { Stack } from '@mui/material';
import Button from '@common/button/Button';
import React from 'react';
import { DeployedCountChip } from '@components/integrations/components/MarketplaceUi';
import { useFormatter } from '../../../../../../components/i18n';

type IngestionCatalogCardDeployButtonProps = {
  deploymentCount?: number;
  deployedTo?: string;
  onClick: () => void;
};

const IngestionCatalogCardDeployButton = ({ deploymentCount = 0, deployedTo, onClick }: IngestionCatalogCardDeployButtonProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Stack direction="row" alignItems="center" gap={1}>
      <DeployedCountChip count={deploymentCount} to={deployedTo} />
      <Button
        size="small"
        onClick={onClick}
      >
        {t_i18n('Deploy')}
      </Button>
    </Stack>
  );
};

export default IngestionCatalogCardDeployButton;
