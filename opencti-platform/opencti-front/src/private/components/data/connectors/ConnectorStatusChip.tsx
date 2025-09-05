import React from 'react';
import { ConnectorsStatus_data$data } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { computeConnectorStatus } from '../../../../utils/Connector';

type ConnectorStatusChipProps = {
  connector: Partial<ConnectorsStatus_data$data['connectors'][0]>
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

  return (
    <ItemBoolean
      status={itemBooleanStatus}
      label={t_i18n(label)}
      variant={'inList'}
    />
  );
};

export default ConnectorStatusChip;
