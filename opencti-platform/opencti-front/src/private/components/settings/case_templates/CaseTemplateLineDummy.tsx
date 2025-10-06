import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { Checkbox, ListItem, ListItemIcon, ListItemText, Skeleton } from '@components';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';

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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface CaseTemplateLineDummyProps {
  dataColumns: DataColumns;
}

const CaseTemplateLineDummy: FunctionComponent<CaseTemplateLineDummyProps> = ({ dataColumns }) => {
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
              <div
                key={label}
                className={classes.bodyItem}
                style={{ width }}
              >
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
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export default CaseTemplateLineDummy;
