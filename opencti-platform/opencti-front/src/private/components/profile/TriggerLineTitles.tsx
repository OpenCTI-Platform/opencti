import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { useFormatter } from '../../../components/i18n';
import { DataColumns } from '../../../components/list_lines';

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

interface TriggerLineTitlesProps {
  dataColumns: DataColumns;
}

const TriggerLineTitles: FunctionComponent<TriggerLineTitlesProps> = ({
  dataColumns,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  return (
    <ListItem classes={{ root: classes.item }} divider={false} button={false}>
      <ListItemIcon></ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.trigger_type.width }}
            >
              {t(dataColumns.trigger_type.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.name.width }}
            >
              {t(dataColumns.name.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.outcomes.width }}
            >
              {t(dataColumns.outcomes.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.event_types.width }}
            >
              {t(dataColumns.event_types.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.filters.width }}
            >
              {t(dataColumns.filters.label)}
            </div>
          </div>
        }
      />
    </ListItem>
  );
};

export default TriggerLineTitles;
