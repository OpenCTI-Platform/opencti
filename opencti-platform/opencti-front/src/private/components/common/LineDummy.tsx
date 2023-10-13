import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Skeleton from '@mui/material/Skeleton';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVertOutlined } from '@mui/icons-material';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { DataColumns } from '../../../components/list_lines';
import { Theme } from '../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
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

const LineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
        <ListItem classes={{ root: classes.item }} divider={true}>
            <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
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
                <MoreVertOutlined />
            </ListItemSecondaryAction>
        </ListItem>
  );
};

export default LineDummy;
