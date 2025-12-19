import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Skeleton from '@mui/material/Skeleton';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Drawer from '@components/common/drawer/Drawer';
import CaseTaskOverview from '@components/cases/tasks/CaseTaskOverview';
import { NorthEastOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { ListItemButton } from '@mui/material';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { tasksDataColumns } from './TasksLine';
import { useFormatter } from '../../../../components/i18n';
import { CaseTasksLine_data$key } from './__generated__/CaseTasksLine_data.graphql';
import TaskPopover from './TaskPopover';
import { CaseTasksLinesQuery$variables } from './__generated__/CaseTasksLinesQuery.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    ...CaseTaskOverview_task
  }
`;

interface CaseTasksLineProps {
  node: CaseTasksLine_data$key;
  entityId?: string;
  paginationOptions: CaseTasksLinesQuery$variables;
  enableReferences: boolean;
}

export const CaseTasksLine: FunctionComponent<CaseTasksLineProps> = ({
  node,
  entityId,
  paginationOptions,
  enableReferences,
}) => {
  const classes = useStyles();
  const { fld } = useFormatter();
  const task = useFragment(CaseTaskFragment, node);
  const [open, setOpen] = useState(false);
  return (
    <>
      <ListItem
        divider={true}
        disablePadding
        secondaryAction={(
          <TaskPopover
            id={task.id}
            objectId={entityId}
            paginationOptions={paginationOptions}
            variant="inLine"
          />
        )}
      >
        <ListItemButton
          classes={{ root: classes.item }}
          onClick={() => setOpen(true)}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <ItemIcon type="Task" />
          </ListItemIcon>
          <ListItemText
            primary={(
              <>
                {Object.values(tasksDataColumns).map((value) => (
                  <div
                    key={value.label}
                    className={classes.bodyItem}
                    style={{ width: value.width }}
                  >
                    {value.render?.(task, { fld, classes })}
                  </div>
                ))}
              </>
            )}
          />
        </ListItemButton>
      </ListItem>
      <Drawer
        open={open}
        title={task.name}
        onClose={() => setOpen(false)}
        header={(
          <IconButton
            aria-label="Go to"
            size="small"
            component={Link}
            to={`/dashboard/cases/tasks/${task.id}`}
            style={{ position: 'absolute', right: 10 }}
          >
            <NorthEastOutlined />
          </IconButton>
        )}
      >
        <CaseTaskOverview tasksData={task} enableReferences={enableReferences} />
      </Drawer>
    </>
  );
};

export const CaseTasksLineDummy = () => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={(
        <IconButton
          disabled={true}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
        >
          <MoreVert />
        </IconButton>
      )}
    >
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
    </ListItem>
  );
};
