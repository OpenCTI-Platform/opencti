import React from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import { MoreVert } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { DeleteOperationsLinesPaginationQuery$variables } from './__generated__/DeleteOperationsLinesPaginationQuery.graphql';
import { DeleteOperationLine_node$key } from './__generated__/DeleteOperationLine_node.graphql';
import DeleteOperationPopover from './DeleteOperationPopover';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import ItemEntityType from '../../../../components/ItemEntityType';

const useStyles = makeStyles((theme: Theme) => ({
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
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

const DeleteOperationFragment = graphql`
  fragment DeleteOperationLine_node on DeleteOperation {
    id
    main_entity_name
    main_entity_type
    deletedBy {
      id
      name
    }
    timestamp
    deleted_elements {
      id
    }
  }
`;

interface DeleteOperationLineComponentProps {
  dataColumns: DataColumns;
  node: DeleteOperationLine_node$key;
  paginationOptions: DeleteOperationsLinesPaginationQuery$variables;
}

export const DeleteOperationLine: React.FC<DeleteOperationLineComponentProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { fldt } = useFormatter();
  const data = useFragment(DeleteOperationFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={data.main_entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.main_entity_type.width }}
            >
              <ItemEntityType entityType={data.main_entity_type} />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.main_entity_name.width }}
            >
              {data.main_entity_name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.deletedBy.width }}
            >
              {data.deletedBy?.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.timestamp.width }}
            >
              {fldt(data.timestamp)}
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <DeleteOperationPopover
          mainEntityId={data.id}
          deletedCount={data.deleted_elements.length}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

interface DeleteOperationLineDummyProps {
  dataColumns: DataColumns;
}

export const DeleteOperationLineDummy: React.FC<DeleteOperationLineDummyProps> = ({ dataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      style={{ minWidth: 40 }}
    >
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
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <IconButton disabled={true} aria-haspopup="true" size="large">
          <MoreVert />
        </IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
