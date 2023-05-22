import React from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';

const useStyles = makeStyles(() => ({
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    borderBottom: '1px solid rgba(255, 255, 255, 0.12)',
  },
  headerItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
}));

const dataColumns: DataColumns = {
  name: {
    label: 'Title',
    width: '25%',
    isSortable: true,
  },
  dueDate: {
    label: 'Due Date',
    width: '15%',
    isSortable: true,
  },
  objectAssignee: {
    label: 'Assignees',
    width: '25%',
    isSortable: true,
  },
  objectLabel: {
    label: 'Labels',
    width: '20%',
    isSortable: true,
  },
  x_opencti_workflow_id: {
    label: 'Status',
    width: '15%',
    isSortable: true,
  },
};

const CaseTasksLineTitles = () => {
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
              style={{ width: dataColumns.name.width }}
            >
              {t(dataColumns.name.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.dueDate.width }}
            >
              {t(dataColumns.dueDate.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.objectAssignee.width }}
            >
              {t(dataColumns.objectAssignee.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              {t(dataColumns.objectLabel.label)}
            </div>
            <div
              className={classes.headerItem}
              style={{ width: dataColumns.x_opencti_workflow_id.width }}
            >
              {t(dataColumns.x_opencti_workflow_id.label)}
            </div>
          </div>
        }
      />
    </ListItem>
  );
};

export default CaseTasksLineTitles;
