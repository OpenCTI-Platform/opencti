import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Avatar from '@mui/material/Avatar';
import { Close } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemAvatar from '@mui/material/ListItemAvatar';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import SubTypeWorkflowStatusAdd from './SubTypeWorkflowStatusAdd';
import { hexToRGB } from '../../../../utils/Colors';
import { Theme } from '../../../../components/Theme';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { SubTypeWorkflowEditionQuery } from './__generated__/SubTypeWorkflowEditionQuery.graphql';
import SubTypeWorkflowStatusPopover from './SubTypeWorkflowStatusPopover';
import { SubTypeWorkflow_subType$data } from './__generated__/SubTypeWorkflow_subType.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
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
      edges {
        node {
          id
          order
          template {
            name
            color
          }
        }
      }
    }
  }
`;

interface SubTypeEditionContainerProps {
  handleClose: () => void,
  queryRef: PreloadedQuery<SubTypeWorkflowEditionQuery>,
}

const SubTypeWorkflow: FunctionComponent<SubTypeEditionContainerProps> = ({
  handleClose,
  queryRef,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(subTypeWorkflowEditionQuery, queryRef);

  if (queryData.subType) {
    const subType = useFragment(subTypeWorkflowEditionFragment, queryData.subType) as SubTypeWorkflow_subType$data;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {`${t('Workflow of')} ${t(`entity_${subType.label}`)}`}
          </Typography>
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <List
            component="nav"
            aria-labelledby="nested-list-subheader"
            className={classes.root}
          >
            {subType.statuses?.edges.filter((currentObject) => Boolean(currentObject.node.template)).map((statusEdge, idx) => {
              const status = statusEdge.node;
              if (status === null || status.template === null) {
                return <ListItemText
                  key={idx}
                  primary={
                    <Skeleton
                      animation="wave"
                      variant="rectangular"
                      width="90%"
                      height="100%"
                    />
                  }
                />;
              }
              return (
                <ListItem
                  key={status.id}
                  classes={{ root: classes.item }}
                  divider={true}
                >
                  <ListItemAvatar>
                    <Avatar
                      variant="square"
                      style={{
                        color: status.template.color,
                        borderColor: status.template.color,
                        backgroundColor: hexToRGB(status.template.color),
                      }}
                    >
                      {status.order}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText primary={status.template.name} />
                  <ListItemSecondaryAction>
                    <SubTypeWorkflowStatusPopover subTypeId={subType.id} statusId={status.id} />
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
          <SubTypeWorkflowStatusAdd subTypeId={subType.id} display={true} />
        </div>
      </div>
    );
  }

  return <Loader variant={LoaderVariant.inElement} />;
};

export default SubTypeWorkflow;
