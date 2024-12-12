import Chip from '@mui/material/Chip';
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
    requestAccessStatus {
      id
      color
      name
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
  const workflowStatus = dataResolved.requestAccessStatus?.map((n) => ({
    id: n?.id,
    color: n?.color,
    name: n?.name,
  }));

  return (
    <>{
      workflowStatus?.map((status, idx) => (
        <Chip
          key={idx}
          variant="outlined"
          label={t_i18n(status?.name) || '-'}
          style={{
            fontSize: 12,
            lineHeight: '12px',
            height: 25,
            margin: 7,
            textTransform: 'uppercase',
            borderRadius: 4,
            width: 100,
            color: status?.color,
            borderColor: status?.color,
            backgroundColor: hexToRGB(
              '#000000',
            ),
          }}
        />
      ))
    }
    </>
  );
};

export default RequestAccessStatus;
