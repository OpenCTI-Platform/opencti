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
import { SubTypeWorkflowDrawerEditionQuery } from './__generated__/SubTypeWorkflowDrawerEditionQuery.graphql';
import SubTypeWorkflowStatusPopover from './SubTypeWorkflowStatusPopover';
import { SubTypeWorkflowDrawer_subType$data } from './__generated__/SubTypeWorkflowDrawer_subType.graphql';
import ItemCopy from '../../../../components/ItemCopy';
import { useFormatter } from '../../../../components/i18n';
import { StatusScopeEnum } from '../../../../utils/statusConstants';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  bodyItem: {
    height: 25,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
}));

export const subTypeWorkflowDrawerEditionQuery = graphql`
  query SubTypeWorkflowDrawerEditionQuery($id: String!) {
    subType(id: $id) {
      ...SubTypeWorkflowDrawer_subType
    }
  }
`;

export const subTypeWorkflowDrawerEditionFragment = graphql`
  fragment SubTypeWorkflowDrawer_subType on SubType {
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

interface SubTypeWorkflowDrawer {
  handleClose: () => void;
  queryRef: PreloadedQuery<SubTypeWorkflowDrawerEditionQuery>;
  open?: boolean;
  scope: string;
}

const SubTypeWorkflowDrawer: FunctionComponent<SubTypeWorkflowDrawer> = ({
  queryRef,
  handleClose,
  open,
  scope,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(subTypeWorkflowDrawerEditionQuery, queryRef);
  if (queryData.subType) {
    const subType = useFragment(
      subTypeWorkflowDrawerEditionFragment,
      queryData.subType,
    ) as SubTypeWorkflowDrawer_subType$data;

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
                      primary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height="100%"
                        />
                      )}
                    />
                  );
                }
                return (
                  <ListItem
                    key={status.id}
                    divider={true}
                    secondaryAction={(
                      <SubTypeWorkflowStatusPopover
                        subTypeId={subType.id}
                        statusId={status.id}
                      />
                    )}
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
                      primary={(
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
                      )}
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

export default SubTypeWorkflowDrawer;
