import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import { CaseTemplateTasksLine_node$key } from './__generated__/CaseTemplateTasksLine_node.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { CaseTemplateTasksLinesPaginationQuery$data } from './__generated__/CaseTemplateTasksLinesPaginationQuery.graphql';
import CaseTemplateTasksPopover from './CaseTemplateTasksPopover';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary?.main,
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
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

export const CaseTemplateTasksLineFragment = graphql`
  fragment CaseTemplateTasksLine_node on TaskTemplate {
    id
    name
    description
  }
`;

interface CaseTemplateTasksLineProps {
  node: CaseTemplateTasksLine_node$key;
  dataColumns: DataColumns;
  paginationOptions: CaseTemplateTasksLinesPaginationQuery$data;
}

export const CaseTemplateTasksLine: FunctionComponent<
CaseTemplateTasksLineProps
> = ({ node, dataColumns, paginationOptions }) => {
  const classes = useStyles();
  const task = useFragment(CaseTemplateTasksLineFragment, node);

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Task" />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(task)}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <CaseTemplateTasksPopover
          paginationOptions={paginationOptions}
          task={task}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

interface CaseTemplateLineDummyProps {
  dataColumns: DataColumns;
}

export const CaseTemplateTasksLineDummy: FunctionComponent<
CaseTemplateLineDummyProps
> = ({ dataColumns }) => {
  const classes = useStyles();

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map(({ label, width }) => (
              <div key={label} className={classes.bodyItem} style={{ width }}>
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={width}
                  height="100%"
                />
              </div>
            ))}
          </div>
        }
      />
    </ListItem>
  );
};
