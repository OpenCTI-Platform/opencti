import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
  headerItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
}));

interface UserLineTitlesProps {
  dataColumns: DataColumns,
}

const UserLineTitles: FunctionComponent<UserLineTitlesProps> = ({ dataColumns }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={false}
    >
      <ListItemIcon >
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.name.width }}
            >
              {t(dataColumns.name.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.user_email.width }}
            >
              {t(dataColumns.user_email.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.firstname.width }}
            >
              {t(dataColumns.firstname.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.lastname.width }}
            >
              {t(dataColumns.lastname.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.otp.width }}
            >
              {t(dataColumns.otp.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.created_at.width }}
            >
              {t(dataColumns.created_at.label)}
            </div>
          </div>
        }
      />
    </ListItem>
  );
};

export default UserLineTitles;
