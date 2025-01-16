import React from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import { useFormatter } from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';

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
    // display: 'inline-flex',
    // flexWrap: 'wrap',
  },
  status: {
    // display: 'inline-flex',
  },
}));

const requestAccessFragment = graphql`
    fragment RequestAccessStatusFragment_entitySetting on EntitySetting {
        id
        target_type
        request_access_workflow {
            approved_workflow_id
            declined_workflow_id
            workflow
        }
    }
`;

interface RequestAccessProps {
  data: RequestAccessStatusFragment_entitySetting$key
}

const RequestAccessStatus = ({ data }: RequestAccessProps) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const dataResolved = useFragment(requestAccessFragment, data);
  if (!dataResolved) return null;
  return (
    <div className={classes.statuses}>
      <div className={classes.status}>
        {t_i18n('Approve to status:')}
        <Chip
          classes={{ root: classes.chip }}
          variant="outlined"
          label={dataResolved?.request_access_workflow?.approved_workflow_id}
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
        {t_i18n('Declined to status:')}
        <Chip
          classes={{ root: classes.chip }}
          variant="outlined"
          label={dataResolved?.request_access_workflow?.declined_workflow_id}
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

export default RequestAccessStatus;
