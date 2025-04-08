import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import { RequestAccessConfigurationEdition_requestAccess$key } from '@components/settings/sub_types/workflow/__generated__/RequestAccessConfigurationEdition_requestAccess.graphql';
import ItemIcon from '../../../../../components/ItemIcon';
import { hexToRGB } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';

export const requestAccessFragment = graphql`
  fragment RequestAccessStatusFragment_requestAccess on RequestAccessConfiguration {
    id
    approved_status {
      id
      template {
        id
        color
        name
      }
    }
    declined_status {
      id
      template {
        id
        color
        name
      }
    }
    approval_admin {
      id
      name
    }
  }
`;

interface RequestAccessStatusProps {
  data: RequestAccessConfigurationEdition_requestAccess$key,
  requestAccessWorkflowDisabled: boolean
}

const RequestAccessStatus: FunctionComponent<RequestAccessStatusProps> = ({
  data, requestAccessWorkflowDisabled,
}) => {
  const { t_i18n } = useFormatter();
  const dataResolved = useFragment(requestAccessFragment, data);
  const approvedToRfiStatus = dataResolved?.approved_status;
  const declinedToRfiStatus = dataResolved?.declined_status;
  const admins = dataResolved?.approval_admin || [];
  const approvedLabel = approvedToRfiStatus ? t_i18n(approvedToRfiStatus?.template?.name) : 'undefined';
  const approvedColor = approvedToRfiStatus?.template?.color ?? '#000000';
  const declinedLabel = declinedToRfiStatus ? t_i18n(declinedToRfiStatus?.template?.name) : 'undefined';
  const declinedColor = declinedToRfiStatus?.template?.color ?? '#000000';

  return (
    <>
      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('On approval move to status:')}
        { requestAccessWorkflowDisabled && (
          <Chip
            key={approvedToRfiStatus?.id}
            variant="outlined"
            label={t_i18n('Disabled')}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 25,
              margin: 7,
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 100,
            }}
          />)}
        { !requestAccessWorkflowDisabled && (
          <Chip
            key={approvedToRfiStatus?.id}
            variant="outlined"
            label={t_i18n(approvedLabel)}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 25,
              margin: 7,
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 100,
              color: approvedColor,
              borderColor: approvedColor,
              backgroundColor: hexToRGB(approvedColor),
            }}
          />
        )}
      </Typography>

      <Typography variant="h3" gutterBottom={true} style={{ marginBottom: 10 }}>
        {t_i18n('On decline move to status:')}
        { requestAccessWorkflowDisabled && (
          <Chip
            key={approvedToRfiStatus?.id}
            variant="outlined"
            label={t_i18n('Disabled')}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 25,
              margin: 7,
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 100,
            }}
          />)}
        { !requestAccessWorkflowDisabled && (
          <Chip
            key={declinedToRfiStatus?.id}
            variant="outlined"
            label={t_i18n(declinedLabel)}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 25,
              margin: 7,
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 100,
              color: declinedColor,
              borderColor: declinedColor,
              backgroundColor: hexToRGB(declinedColor),
            }}
          />
        )}
      </Typography>
      <Typography variant="h3" gutterBottom={true} style={{ marginBottom: 10 }}>
        {t_i18n('Validator membership:')}
      </Typography>
      {!requestAccessWorkflowDisabled && admins.map((member) => {
        return (
          <ListItemButton
            key={member?.id}
            dense={true}
            divider={true}
          >
            <ListItemIcon>
              <ItemIcon type="group" />
            </ListItemIcon>
            <ListItemText primary={member?.name}/>
          </ListItemButton>
        );
      })}
    </>
  );
};

export default RequestAccessStatus;
