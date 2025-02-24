import React from 'react';
import Chip from '@mui/material/Chip';
import { ArrowRightAltOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import { useFormatter } from './i18n';
import { hexToRGB } from '../utils/Colors';
import { StatusScope } from './__generated__/ItemStatusTemplate_global.graphql';

export interface StatusTemplateType {
  id: string,
  color: string,
  name: string,
}

export interface StatusType {
  template: StatusTemplateType,
  id: string,
  order: number
}

interface ItemStatusTemplateProps {
  statuses: StatusType[],
  disabled: boolean,
  scope: StatusScope,
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

  const statusByOrder = Object.values(Object.groupBy(statuses, (({ order }) => order)));
  return (
    <div style={{
      display: 'inline-flex',
      flexWrap: 'wrap',
      alignItems: 'center',
    }}
    >
      {statusByOrder.map((statusesForIndex, order) => (
        <div key={`statuses-order-${order}`}
          style={{ display: 'inline-flex', alignItems: 'center', marginBottom: 8 }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {
              statusesForIndex?.map((status) => (
                <div key={status.id}>
                  <Chip
                    variant="outlined"
                    label={status.template?.name}
                    style={{
                      fontSize: 12,
                      lineHeight: '12px',
                      height: 25,
                      marginRight: 7,
                      textTransform: 'uppercase',
                      borderRadius: 4,
                      width: 100,
                      color: status.template?.color,
                      borderColor: status.template?.color,
                      backgroundColor: hexToRGB(
                        status.template?.color ?? '#000000',
                      ),
                    }}
                  />
                </div>
              ))
            }
          </div>
          {
            order < statusByOrder.length - 1 && (
              <Box sx={{ display: 'flex', marginRight: 1 }}>
                <ArrowRightAltOutlined/>
              </Box>
            )
          }
        </div>
      ))}
    </div>
  );
};
export default ItemStatusTemplate;
