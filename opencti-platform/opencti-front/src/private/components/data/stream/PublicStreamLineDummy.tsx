import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';

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
    height: 40,
    display: 'flex',
    alignItems: 'center',
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

interface PublicStreamLineDummyProps {
  dataColumns: DataColumns;
}

const PublicStreamLineDummy = ({ dataColumns }: PublicStreamLineDummyProps) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={<MoreVert classes={classes.itemIconDisabled} />}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.description.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.id.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.stream_public.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.stream_live.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.consumers.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
          </div>
        )}
      />
    </ListItem>
  );
};

export default PublicStreamLineDummy;
