import React from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { ArrowRightAltOutlined } from '@mui/icons-material';
import { SubTypeQuery$data } from '@components/settings/sub_types/__generated__/SubTypeQuery.graphql';
import { useFormatter } from './i18n';
import { hexToRGB } from '../utils/Colors';

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
  arrow: {
    marginRight: 7,
  },
  statuses: {
    display: 'inline-flex',
    flexWrap: 'wrap',
  },
  status: {
    display: 'inline-flex',
  },
}));

interface ItemStatusTemplateProps {
  statuses: NonNullable<SubTypeQuery$data['subType']>['statuses'],
  disabled: boolean
}

const ItemStatusTemplate = ({ statuses, disabled }: ItemStatusTemplateProps) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  if (disabled || statuses.length === 0) {
    return (
      <Chip
        classes={{ root: classes.chip }}
        variant="outlined"
        label={disabled ? t_i18n('Disabled') : t_i18n('Unknown')}
      />
    );
  }

  return (
    <div className={classes.statuses}>
      {statuses.map((status, idx) => (
        <div key={status.id} className={classes.status}>
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
          {idx < statuses.length - 1
            && (
              <div className={classes.arrow}>
                <ArrowRightAltOutlined />
              </div>
            )
          }
        </div>
      ))}
    </div>
  );
};

export default ItemStatusTemplate;
