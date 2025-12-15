import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Checkbox from '@mui/material/Checkbox';
import { Link } from 'react-router-dom';
import Skeleton from '@mui/material/Skeleton';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { ListItemButton } from '@mui/material';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { TasksLine_node$data, TasksLine_node$key } from './__generated__/TasksLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemStatus from '../../../../components/ItemStatus';
import ItemDueDate from '../../../../components/ItemDueDate';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
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
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

export const TaskFragment = graphql`
  fragment TasksLine_node on Task {
    id
    standard_id
    name
    due_date
    description
    workflowEnabled
    entity_type
    draftVersion {
      draft_id
      draft_operation
    }
    objectMarking {
      definition
      definition_type
      id
    }
    objectLabel {
      id
      value
      color
    }
    objectAssignee {
      entity_type
      id
      name
    }
    status {
      template {
        name
        color
      }
    }
  }
`;

export const tasksDataColumns: DataColumns = {
  name: {
    label: 'Name',
    width: '35%',
    isSortable: true,
    render: (task: TasksLine_node$data) => (
      <Tooltip title={task.name}>
        <span>{task.name}</span>
      </Tooltip>
    ),
  },
  due_date: {
    label: 'Due Date',
    width: '12%',
    isSortable: true,
    render: (task: TasksLine_node$data) => (
      <ItemDueDate due_date={task.due_date} variant="inList" />
    ),
  },
  objectAssignee: {
    label: 'Assignees',
    width: '18%',
    isSortable: true,

    render: (task: TasksLine_node$data) => ((task.objectAssignee ?? []).length > 0
      ? (task.objectAssignee ?? []).map((node) => node.name).join(', ')
      : '-'),
  },
  objectLabel: {
    label: 'Labels',
    width: '18%',
    isSortable: false,
    render: (task: TasksLine_node$data) => (
      <StixCoreObjectLabels variant="inList" labels={task.objectLabel} />
    ),
  },
  x_opencti_workflow_id: {
    label: 'Status',
    width: '15%',
    isSortable: true,
    render: (task: TasksLine_node$data) => (
      <ItemStatus
        status={task.status}
        variant="inList"
        disabled={!task.workflowEnabled}
      />
    ),
  },
};

interface TasksLineProps {
  node: TasksLine_node$key;
  onLabelClick: HandleAddFilter;
  selectedElements: Record<string, TasksLine_node$data>;
  deSelectedElements: Record<string, TasksLine_node$data>;
  onToggleEntity: (
    entity: TasksLine_node$data,
    event: React.SyntheticEvent,
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: TasksLine_node$data,
    event: React.SyntheticEvent,
  ) => void;
  index: number;
}

export const TasksLine: FunctionComponent<TasksLineProps> = ({
  node,
  deSelectedElements,
  onToggleEntity,
  selectAll,
  selectedElements,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { fld } = useFormatter();
  const data = useFragment(TaskFragment, node);

  return (
    <ListItemButton
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`/dashboard/cases/tasks/${data.id}`}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, data, event)
          : onToggleEntity(data, event))
        }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Task" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(tasksDataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(data, { fld, classes })}
              </div>
            ))}
          </div>
        )}
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const TasksLineDummy = () => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
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
        )}
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
