import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';

export const requestAccessFragment = graphql`
  fragment RequestAccessStatusFragment_entitySetting on EntitySetting {
    id
    target_type
    request_access_workflow {
      approved_workflow_id
      declined_workflow_id
      workflow
    }
    requestAccessApprovedStatus {
        id
        template {
            id
            color
            name
        }
    }
    requestAccessDeclinedStatus {
        id
        template {
            id
            color
            name
        }
    }
  }
`;

interface RequestAccessStatusProps {
  data: RequestAccessStatusFragment_entitySetting$key
}

const RequestAccessStatus: FunctionComponent<RequestAccessStatusProps> = ({
  data,
}) => {
  const { t_i18n } = useFormatter();
  const dataResolved = useFragment(requestAccessFragment, data);
  const approvedToRfiStatus = dataResolved.requestAccessApprovedStatus;
  const declinedToRfiStatus = dataResolved.requestAccessDeclinedStatus;
  return (
    <>
      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('On approval move to status:')}
        <Chip
          key={approvedToRfiStatus?.id}
          variant="outlined"
          label={approvedToRfiStatus ? t_i18n(approvedToRfiStatus?.template?.name) : '-'}
          style={{
            fontSize: 12,
            lineHeight: '12px',
            height: 25,
            margin: 7,
            textTransform: 'uppercase',
            borderRadius: 4,
            width: 100,
            color: approvedToRfiStatus?.template?.color,
            borderColor: approvedToRfiStatus?.template?.color,
            backgroundColor: hexToRGB(
              '#000000',
            ),
          }}
        />
      </Typography>

      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('On decline move to status:')}
        <Chip
          key={declinedToRfiStatus?.id}
          variant="outlined"
          label={declinedToRfiStatus ? t_i18n(declinedToRfiStatus?.template?.name) : '-'}
          style={{
            fontSize: 12,
            lineHeight: '12px',
            height: 25,
            margin: 7,
            textTransform: 'uppercase',
            borderRadius: 4,
            width: 100,
            color: declinedToRfiStatus?.template?.color,
            borderColor: declinedToRfiStatus?.template?.color,
            backgroundColor: hexToRGB(
              '#000000',
            ),
          }}
        />
      </Typography>

      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('Validator membership:')} TODO
      </Typography>
    </>
  );
};

export default RequestAccessStatus;
