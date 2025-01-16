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
  statuses: {
    display: 'inline-flex',
    flexWrap: 'wrap',
  },
  status: {
    display: 'inline-flex',
  },
}));

interface ItemStatusTemplateProps {
  configuration: NonNullable<SubTypeQuery$data['subType']>['request_access_workflow'],
  disabled: boolean
}

const ItemRequestAccessStatus = ({ configuration, disabled }: ItemStatusTemplateProps) => {
  const { t_i18n } = useFormatter();
  console.log('COFNIG:', { configuration });
  const classes = useStyles();
  if (disabled || configuration?.workflow?.length === 0) {
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
      <div className={classes.status}>
        Approve to status:
        <Chip
          classes={{ root: classes.chip }}
          variant="outlined"
          label={configuration?.approved_workflow_id}
          style={{
            color: '#fff',
            borderColor: '#000',
            backgroundColor: hexToRGB(
              '#000000',
            ),
          }}
        />
      </div>

      <div className={classes.status}>
        Declined to status:
        <Chip
          classes={{ root: classes.chip }}
          variant="outlined"
          label={configuration?.declined_workflow_id}
          style={{
            color: '#fff',
            borderColor: '#000',
            backgroundColor: hexToRGB(
              '#000000',
            ),
          }}
        />
      </div>
    </div>
  );
};

export default ItemRequestAccessStatus;
