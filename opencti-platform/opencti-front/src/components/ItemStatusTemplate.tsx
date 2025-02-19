import React from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { ArrowRightAltOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from './i18n';
import { hexToRGB } from '../utils/Colors';
import { ItemStatusTemplate_global$key } from './__generated__/ItemStatusTemplate_global.graphql';
import { StatusScopeEnum } from '../utils/statusConstants';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 100,
  },
  container: {
    display: 'inline-flex',
    flexWrap: 'wrap',
    alignItems: 'center',
  },
  order: {
    display: 'inline-flex',
    alignItems: 'center',
    marginBottom: 8,
  },
  statuses: {
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
  },
}));

interface ItemStatusTemplateProps {
  data: ItemStatusTemplate_global$key,
  disabled: boolean,
  scope: string,
}

const itemStatusTemplateGlobalFragment = graphql`
 fragment ItemStatusTemplate_global on SubType {
   statuses {
     id
     scope
     order
     template {
       id
       name
       color
     }
   }
   statusesRequestAccess {
       id
       order
       scope
       template {
           id
           name
           color
       }
   }
 }
`;

const ItemStatusTemplate = ({ data, disabled, scope }: ItemStatusTemplateProps) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const statusesData = useFragment(itemStatusTemplateGlobalFragment, data);

  let statuses = statusesData.statuses ?? [];
  if (scope === StatusScopeEnum.REQUEST_ACCESS) {
    statuses = statusesData.statusesRequestAccess ?? [];
  }

  if (disabled) {
    return (
      <Chip
        classes={{ root: classes.chip }}
        variant="outlined"
        label={t_i18n('Disabled')}
      />
    );
  }

  const statusByOrder = Object.values(Object.groupBy(statuses, (({ order }) => order)));
  return (
    <div className={classes.container}>
      {statusByOrder.map((statusesForIndex, order) => (
        <div key={`statuses-order-${order}`} className={classes.order}>
          <div className={classes.statuses}>
            {
              statusesForIndex?.map((status) => (
                <div key={status.id}>
                  <Chip
                    classes={{ root: classes.chip }}
                    variant="outlined"
                    label={status.template?.name}
                    style={{
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
