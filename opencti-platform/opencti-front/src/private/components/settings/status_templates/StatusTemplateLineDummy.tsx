import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Skeleton from '@mui/material/Skeleton';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import Box from '@mui/material/Box';
import type { Theme } from '../../../../components/Theme';
import { DataColumnsType } from './StatusTemplateLine';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
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

interface StatusTemplateLineDummyProps {
  dataColumns: DataColumnsType;
}

const StatusTemplateLineDummy: FunctionComponent<
StatusTemplateLineDummyProps
> = ({ dataColumns }) => {
  const classes = useStyles();

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <Box sx={{ root: classes.itemIconDisabled }}>
          <IconButton disabled={true} aria-haspopup="true" size="large">
            <MoreVert/>
          </IconButton>
        </Box>
      }
    >
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.color.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.usages.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
          </div>
        }
      />
    </ListItem>
  );
};

export default StatusTemplateLineDummy;
