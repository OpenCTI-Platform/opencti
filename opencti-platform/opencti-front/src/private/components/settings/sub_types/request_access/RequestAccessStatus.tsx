import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/request_access/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import ItemIcon from '../../../../../components/ItemIcon';
import { hexToRGB } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';

export const requestAccessFragment = graphql`
  fragment RequestAccessStatusFragment_entitySetting on EntitySetting {
    id
    target_type
    requestAccessConfiguration {
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
            type
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
  const approvedToRfiStatus = dataResolved?.requestAccessConfiguration?.approved_status;
  const declinedToRfiStatus = dataResolved?.requestAccessConfiguration?.declined_status;
  const admins = dataResolved?.requestAccessConfiguration?.approval_admin || [];
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

      <Typography variant="h3" gutterBottom={true} style={{ marginBottom: 10 }}>
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
      <Typography variant="h3" gutterBottom={true} style={{ marginBottom: 10 }}>
        {t_i18n('Validator membership:')}
      </Typography>
      {admins.map((member) => {
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
