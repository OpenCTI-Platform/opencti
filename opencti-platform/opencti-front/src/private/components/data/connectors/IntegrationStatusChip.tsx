import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import type { IntegrationStatus } from '../../../../utils/Connector';

interface IntegrationStatusChipProps {
  status: IntegrationStatus;
}

// The status chip of every integration (connector or feed), in the list and on the details page:
// active = green, inactive = gray, processing (starting or stopping) = spinner only
const IntegrationStatusChip = ({ status }: IntegrationStatusChipProps) => {
  const { t_i18n } = useFormatter();
  if (status === 'processing') return <ItemBoolean status={undefined} />;
  if (status === 'active') return <ItemBoolean status label={t_i18n('Started')} />;
  return <ItemBoolean status={null} neutralLabel={t_i18n('Stopped')} />;
};

export default IntegrationStatusChip;
