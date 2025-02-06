import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Box from '@mui/material/Box';
import SubTypeWorkflowStatusPopover from '@components/settings/sub_types/SubTypeWorkflowStatusPopover';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import RequestAccessStatusPopover from '@components/settings/sub_types/RequestAccessStatusPopover';
import CreatorField from '@components/common/form/CreatorField';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import { Option } from '@components/common/form/ReferenceField';
import { hexToRGB } from '../../../../utils/Colors';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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
      request_access_workflow {
          approval_admin
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
  console.log('RequestAccessWorkflow.tsx => queryData', queryData);
  const approvedToRfiStatus = queryData.requestAccessApprovedStatus;
  const declinedToRfiStatus = queryData.requestAccessDeclinedStatus;
  const onCreatorChange = (value) => {
    console.log('On change', value);
  };
  const setFieldValue = (field: string, value: Option) => {
    console.log('setFieldValue', value);
  };
  return (
    <Drawer
      open={open}
      title={t_i18n('Request Access Configuration')}
      onClose={handleClose}
    >
      <>
        <List
          component="nav"
          aria-labelledby="nested-list-subheader"
        >

          <ListItem
            key={approvedToRfiStatus?.id}
            divider={true}
          >
            <ListItemText
              primary={
                <>
                  <div
                    style={{
                      height: 40,
                      fontSize: 13,
                      float: 'left',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      paddingRight: 10,
                      width: '100%',
                    }}
                  >
                    <Typography>
                      On approval move to status:
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
                  </div>
                </>
              }
            />
            <ListItemSecondaryAction>
              <RequestAccessStatusPopover
                subTypeId={'Case-Rfi'}
                statusId={approvedToRfiStatus?.id}
              />
            </ListItemSecondaryAction>
          </ListItem>

          <ListItem
            key={declinedToRfiStatus?.id}
            divider={true}
          >
            <ListItemText
              primary={
                <>
                  <div
                    style={{
                      height: 40,
                      fontSize: 13,
                      float: 'left',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      paddingRight: 10,
                      width: '100%',
                    }}
                  >
                    <Typography>
                      On decline move to status:
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
                  </div>
                </>
              }
            />
            <ListItemSecondaryAction>
              <RequestAccessStatusPopover
                subTypeId={'Case-Rfi'}
                statusId={declinedToRfiStatus?.id}
              />
            </ListItemSecondaryAction>
          </ListItem>

          <ListItem
            key={1234}
            divider={true}
          >
            <ListItemText
              primary={
                <>
                  <div
                    style={{
                      height: 40,
                      fontSize: 13,
                      float: 'left',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      paddingRight: 10,
                      width: '100%',
                    }}
                  >

                  </div>
                </>
              }
            />
          </ListItem>

        </List>
      </>
    </Drawer>
  );
};

export default RequestAccessWorkflow;
