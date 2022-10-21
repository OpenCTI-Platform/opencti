import React from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { LabelOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import { graphql, useFragment } from 'react-relay';
import StatusTemplatePopover from './StatusTemplatePopover';

const useStyles = makeStyles((theme) => ({
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
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
}));

export const StatusTemplateLineFragment = graphql`
    fragment StatusTemplateLine_node on StatusTemplate {
        id
        name
        color
    }
`;

const StatusTemplateLine = ({ node, dataColumns, paginationOptions }) => {
  const classes = useStyles();

  const data = useFragment(StatusTemplateLineFragment, node);

  return (
    <ListItemButton classes={{ root: classes.item }} divider={true}>
      <ListItemIcon style={{ color: data.color }}>
        <LabelOutline />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.color.width }}
            >
              {data.color}
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <StatusTemplatePopover
          statusTemplateId={data.id}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItemButton>

  );
};

export default StatusTemplateLine;
