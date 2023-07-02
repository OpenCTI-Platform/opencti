import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Skeleton from '@mui/material/Skeleton';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import ItemIcon from '../../../../components/ItemIcon';
import { Theme } from '../../../../components/Theme';
import { tasksDataColumns } from './TasksLine';
import { useFormatter } from '../../../../components/i18n';
import { CaseTasksLine_data$key } from './__generated__/CaseTasksLine_data.graphql';
import TaskPopover from './TaskPopover';
import { CaseTasksLinesQuery$variables } from './__generated__/CaseTasksLinesQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 15,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
    minWidth: 52,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    borderRadius: 5,
  },
}));

const CaseTaskFragment = graphql`
  fragment CaseTasksLine_data on Task {
    id
    standard_id
    name
    due_date
    description
    workflowEnabled
    objectMarking {
      edges {
        node {
          definition
          definition_type
          id
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    objectAssignee {
      edges {
        node {
          entity_type
          id
          name
        }
      }
    }
    status {
      template {
        name
        color
      }
    }
  }
`;

interface CaseTasksLineProps {
  node: CaseTasksLine_data$key;
  entityId?: string;
  paginationOptions: CaseTasksLinesQuery$variables;
}

export const CaseTasksLine: FunctionComponent<CaseTasksLineProps> = ({
  node,
  entityId,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { fld } = useFormatter();
  const task = useFragment(CaseTaskFragment, node);
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/cases/tasks/${task.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Task" />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(tasksDataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(task, { fld, classes })}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <TaskPopover
          id={task.id}
          objectId={entityId}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const CaseTasksLineDummy = () => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(tasksDataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <IconButton
          disabled={true}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          size="large"
        >
          <MoreVert />
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
