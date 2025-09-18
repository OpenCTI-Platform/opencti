import React from 'react';
import { ConnectorsStateQuery$data } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { computeConnectorStatus } from '../../../../utils/Connector';

type ConnectorStatusChipProps = {
  connector: Partial<ConnectorsStateQuery$data['connectors'][0]>
};

const ConnectorStatusChip: React.FC<ConnectorStatusChipProps> = ({ connector }) => {
  const { t_i18n } = useFormatter();
  const { status, label, processing } = computeConnectorStatus(connector);

  let itemBooleanStatus: boolean | undefined;

  if (processing) {
    itemBooleanStatus = undefined;
  } else if (status === 'active') {
    itemBooleanStatus = true;
  } else {
    itemBooleanStatus = false;
  }

  const getTranslatedLabel = (labelValue: string) => {
    switch (labelValue) {
      case 'starting':
        return t_i18n('Starting');
      case 'stopping':
        return t_i18n('Stopping');
      case 'stopped':
        return t_i18n('Stopped');
      case 'started':
        return t_i18n('Started');
      case 'active':
        return t_i18n('Active');
      case 'inactive':
        return t_i18n('Inactive');
      default:
        return t_i18n(label);
    }
  };

  return (
    <ItemBoolean
      status={itemBooleanStatus}
      label={getTranslatedLabel(label)}
      variant={'inList'}
    />
  );
};

export default ConnectorStatusChip;
