import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ItemIcon from '../../../../components/ItemIcon';
import { Theme } from '../../../../components/Theme';
import { tasksDataColumns } from './TasksLine';
import { useFormatter } from '../../../../components/i18n';
import { CaseTasksLine_data$key } from './__generated__/CaseTasksLine_data.graphql';
import TaskPopover from './TaskPopover';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 15,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
  },
  labelInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
  },
}));

const CaseTaskFragment = graphql`
  fragment CaseTasksLine_data on Task {
    id
    name
    dueDate
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
}

const CaseTasksLine: FunctionComponent<CaseTasksLineProps> = ({ node }) => {
  const classes = useStyles();
  const { fldt } = useFormatter();
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
        <ItemIcon type="Task"></ItemIcon>
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
                {value.render?.(task, { fldt, classes })}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <TaskPopover id={task.id} />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export default CaseTasksLine;
