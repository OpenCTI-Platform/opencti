import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemAvatar from '@mui/material/ListItemAvatar/ListItemAvatar';
import Avatar from '@mui/material/Avatar';
import ListItemText from '@mui/material/ListItemText/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import RequestAccessWorkflowStatusPopover from '@components/settings/sub_types/RequestAccessWorkflowStatusPopover';
import { WorkflowStatusEditFormData } from '@components/settings/sub_types/RequestAccessWorkflowStatusEdit';
import { hexToRGB } from '../../../../utils/Colors';
import { useFormatter } from '../../../../components/i18n';
import ItemCopy from '../../../../components/ItemCopy';

export const requestAccessWorkflowEditionQuery = graphql`
  query RequestAccessWorkflowEditionQuery($id: String!) {
    entitySetting(id: $id) {
      ...RequestAccessStatusFragment_entitySetting
    }
  }
`;

const requestAccessWorkflowFragment = graphql`
  fragment RequestAccessWorkflow_entitySettings on EntitySetting {
    id
    request_access_workflow {
      approved_workflow_id
      declined_workflow_id
      approval_admin
    }
    requestAccessStatus {
      color
      name
      id
    }
  }
`;

interface RequestAccessWorkflowProps {
  handleClose: () => void;
  queryRef: RequestAccessStatusFragment_entitySetting$key
  open?: boolean
}

const RequestAccessWorkflow: FunctionComponent<RequestAccessWorkflowProps> = ({
  handleClose,
  open,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const queryData = useFragment(requestAccessWorkflowFragment, queryRef);
  const changeStatus = (values: WorkflowStatusEditFormData, statusId: string) => {
    console.log('coucou', values);
    console.log('statusId', statusId);
    console.log('approved_workflow', queryData.request_access_workflow?.approved_workflow_id);
    console.log('statusId', statusId === queryData.request_access_workflow?.approved_workflow_id);
  };

  return (
    <Drawer
      open={open}
      title={t_i18n('Request Access Workflow')}
      onClose={handleClose}
    >
      <>
        <List
          component="nav"
          aria-labelledby="nested-list-subheader"
        >
          {queryData.requestAccessStatus?.map((status) => {
            return (
              <ListItem
                key={status?.id}
                divider={true}
              >
                <ListItemAvatar>
                  <Avatar
                    variant="square"
                    style={{
                      color: status?.color,
                      borderColor: status?.color,
                      backgroundColor: hexToRGB(status?.color),
                    }}
                  >
                    {'0'}
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary={
                    <>
                      <div
                        style={{
                          height: 20,
                          fontSize: 13,
                          float: 'left',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          paddingRight: 10,
                          width: '30%',
                        }}
                      >
                        {status?.name ?? ''}
                      </div>
                      <div
                        style={{
                          height: 20,
                          fontSize: 13,
                          float: 'left',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          paddingRight: 10,
                          width: '60%',
                        }}
                      >
                        <ItemCopy content={status?.id ?? ''} variant="inLine" />
                      </div>
                    </>
                  }
                />
                <ListItemSecondaryAction>
                  <RequestAccessWorkflowStatusPopover
                    entitySettingId={queryData.id}
                    onStatusChange={(values) => changeStatus(values, status?.id ?? '')}
                  />
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
      </>
    </Drawer>
  );
};

export default RequestAccessWorkflow;
