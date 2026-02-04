import React from 'react';
import Chip from '@mui/material/Chip';
import { ArrowRightAltOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import { useFormatter } from './i18n';
import { hexToRGB } from '../utils/Colors';
import Tag from './common/tag/Tag';
import { Stack } from '@mui/material';

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
}

const ItemStatusTemplate = ({ statuses, disabled }: ItemStatusTemplateProps) => {
  const { t_i18n } = useFormatter();

  if (disabled) {
    return (
      <Chip
        style={{ fontSize: 12,
          lineHeight: '12px',
          height: 25,
          marginRight: 7,
          textTransform: 'uppercase',
          borderRadius: 4,
          width: 100 }}
        variant="outlined"
        label={t_i18n('Disabled')}
      />
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
    </Stack>
  );
};
export default ItemStatusTemplate;
