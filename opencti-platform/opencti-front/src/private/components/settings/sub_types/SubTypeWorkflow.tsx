import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Avatar from '@mui/material/Avatar';
import ListItem from '@mui/material/ListItem';
import ListItemAvatar from '@mui/material/ListItemAvatar';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import Skeleton from '@mui/material/Skeleton';
import Drawer from '@components/common/drawer/Drawer';
import SubTypeWorkflowStatusAdd from './SubTypeWorkflowStatusAdd';
import { hexToRGB } from '../../../../utils/Colors';
import { SubTypeWorkflowEditionQuery } from './__generated__/SubTypeWorkflowEditionQuery.graphql';
import SubTypeWorkflowStatusPopover from './SubTypeWorkflowStatusPopover';
import { SubTypeWorkflow_subType$data } from './__generated__/SubTypeWorkflow_subType.graphql';
import ItemCopy from '../../../../components/ItemCopy';
import { useFormatter } from '../../../../components/i18n';
import { StatusScopeEnum } from '../../../../utils/statusConstants';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
}));

export const subTypeWorkflowEditionQuery = graphql`
  query SubTypeWorkflowEditionQuery($id: String!) {
    subType(id: $id) {
      ...SubTypeWorkflow_subType
    }
  }
`;

export const subTypeWorkflowEditionFragment = graphql`
  fragment SubTypeWorkflow_subType on SubType {
    id
    label
    workflowEnabled
    statuses {
      id
      order
      scope
      template {
        name
        color
      }
    }
    statusesRequestAccess {
          id
          order
          scope
          template {
              name
              color
          }
      } 
  }
`;

interface SubTypeEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<SubTypeWorkflowEditionQuery>
  open?: boolean
  scope: string
}

const SubTypeWorkflow: FunctionComponent<SubTypeEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
  scope,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(subTypeWorkflowEditionQuery, queryRef);
  if (queryData.subType) {
    const subType = useFragment(
      subTypeWorkflowEditionFragment,
      queryData.subType,
    ) as SubTypeWorkflow_subType$data;

    let statusesToDisplay = subType.statuses;
    if (scope === StatusScopeEnum.REQUEST_ACCESS) {
      statusesToDisplay = subType.statusesRequestAccess;
    }

    return (
      <Drawer
        open={open}
        title={`${t_i18n('Workflow of')} ${t_i18n(`entity_${subType.label}`)}`}
        onClose={handleClose}
      >
        <>
          <List
            component="nav"
            aria-labelledby="nested-list-subheader"
          >
            {statusesToDisplay?.filter((status) => Boolean(status.template))
              .map((status, idx) => {
                if (status === null || status.template === null) {
                  return (
                    <ListItemText
                      key={idx}
                      primary={
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height="100%"
                        />
                      }
                    />
                  );
                }
                return (
                  <ListItem
                    key={status.id}
                    divider={true}
                    secondaryAction={
                      <SubTypeWorkflowStatusPopover
                        subTypeId={subType.id}
                        statusId={status.id}
                      />
                    }
                  >
                    <ListItemAvatar>
                      <Avatar
                        variant="square"
                        style={
                          status.template && {
                            color: status.template.color,
                            borderColor: status.template.color,
                            backgroundColor: hexToRGB(status.template.color),
                          }}
                      >
                        {status.order}
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={
                        <>
                          <div
                            className={classes.bodyItem}
                            style={{ width: '30%' }}
                          >
                            {status.template?.name ?? ''}
                          </div>
                          <div
                            className={classes.bodyItem}
                            style={{ width: '60%' }}
                          >
                            <ItemCopy content={status.id} variant="inLine" />
                          </div>
                        </>
                      }
                    />
                  </ListItem>
                );
              })}
          </List>
          <SubTypeWorkflowStatusAdd subTypeId={subType.id} display={true} scope={scope} />
        </>
      </Drawer>
    );
  }
  return <div />;
};

export default SubTypeWorkflow;
