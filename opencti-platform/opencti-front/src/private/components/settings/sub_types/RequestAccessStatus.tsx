import Chip from '@mui/material/Chip';
import { graphql, useFragment } from 'react-relay';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import React from 'react';
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
        requestAccessStatus {
            id
            color
            name
        }
    }
`;

interface RequestAccessProps {
  data: RequestAccessStatusFragment_entitySetting$key
}

const RequestAccessStatus = ({ data }: RequestAccessProps) => {
  const { t_i18n } = useFormatter();
  const dataResolved = useFragment(requestAccessFragment, data);
  if (!dataResolved) return null;
  let approvedStatus;
  if (dataResolved.requestAccessStatus && dataResolved.request_access_workflow) {
    approvedStatus = dataResolved.requestAccessStatus.find((status) => status?.id === dataResolved?.request_access_workflow?.approved_workflow_id);
  }

  let declinedStatus;
  if (dataResolved.requestAccessStatus && dataResolved.request_access_workflow) {
    declinedStatus = dataResolved.requestAccessStatus.find((status) => status?.id === dataResolved?.request_access_workflow?.declined_workflow_id);
  }

  // const [displayStatusList, setDisplayStatusList] = useState<boolean>(false);
  // const handleOpenDeclineUpdate = () => { setDisplayStatusList(true); };
  // const handleOpenApproveUpdate = () => { setDisplayStatusList(true); };
  return (
    <>
      <div>
        <div>
          {t_i18n('Approve to status:')}
          <Chip
            variant="outlined"
            label={approvedStatus?.name || '-'}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 25,
              margin: 7,
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 100,
              color: approvedStatus?.color,
              borderColor: approvedStatus?.color,
              backgroundColor: hexToRGB(
                '#000000',
              ),
            }}
          />
        </div>

        <div>
          {t_i18n('Declined to status:')}
          <Chip
            variant="outlined"
            label={declinedStatus?.name}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 25,
              margin: 7,
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 100,
              color: declinedStatus?.color,
              borderColor: declinedStatus?.color,
              backgroundColor: hexToRGB(
                '#000000',
              ),
            }}
          />
        </div>
      </div>
      <div>
        {t_i18n('Request access admin:')}
        <Chip
          variant="outlined"
          label={'TODO UNE ORGA'}
          style={{
            fontSize: 12,
            lineHeight: '12px',
            height: 25,
            margin: 7,
            textTransform: 'uppercase',
            borderRadius: 4,
            width: 100,
            backgroundColor: hexToRGB(
              '#000000',
            ),
          }}
        />
      </div>
    </>
  );
};

export default RequestAccessStatus;
