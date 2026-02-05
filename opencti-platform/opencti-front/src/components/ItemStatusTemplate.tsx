import { ArrowRightAltOutlined } from '@mui/icons-material';
import { Stack } from '@mui/material';
import React, { ReactElement } from 'react';
import { hexToRGB } from '../utils/Colors';
import Tag from './common/tag/Tag';
import { useFormatter } from './i18n';

export interface StatusTemplateType {
  id: string;
  color: string;
  name: string;
}

export interface StatusType {
  template: StatusTemplateType;
  id: string;
  order: number;
}

interface ItemStatusTemplateProps {
  statuses: StatusType[];
  disabled: boolean;
  actionComponent?: ReactElement;
}

const ItemStatusTemplate = ({ statuses, disabled, actionComponent }: ItemStatusTemplateProps) => {
  const { t_i18n } = useFormatter();

  if (disabled) {
    return (
      <Tag label={t_i18n('Disabled')} disabled />
    );
  }

  const statusByOrder = Object.values(Object.groupBy(statuses, ({ order }) => order));

  return (
    <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
      {statusByOrder.map((statusesForIndex, index) => (
        <React.Fragment key={`statuses-order-${index}`}>
          <Stack direction="column" gap={1}>
            {statusesForIndex?.map((status) => (
              <Tag
                key={status.id}
                label={status.template?.name}
                color={hexToRGB(status.template?.color ?? '#000000')}
              />
            ))}
          </Stack>
          {index < statusByOrder.length - 1 && (
            <ArrowRightAltOutlined />
          )}
        </React.Fragment>
      ))}
      {actionComponent}
    </Stack>
  );
};
export default ItemStatusTemplate;
