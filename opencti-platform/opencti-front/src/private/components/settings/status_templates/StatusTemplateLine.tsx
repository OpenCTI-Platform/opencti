import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { FactCheckOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import { graphql, useFragment } from 'react-relay';
import StatusTemplatePopover from './StatusTemplatePopover';
import { Theme } from '../../../../components/Theme';
import { StatusTemplateLine_node$key } from './__generated__/StatusTemplateLine_node.graphql';

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
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

export type DataColumnsType = {
  name: {
    label: string;
    width: string;
    isSortable: boolean;
  };
  color: {
    label: string;
    width: string;
    isSortable: boolean;
  };
  usages: {
    label: string;
    width: string;
    isSortable: boolean;
  };
};

export const StatusTemplateLineFragment = graphql`
  fragment StatusTemplateLine_node on StatusTemplate {
    id
    name
    color
    usages
  }
`;

interface StatusTemplateLineProps {
  node: StatusTemplateLine_node$key;
  dataColumns: DataColumnsType;
  paginationOptions: { search: string; orderMode: string; orderBy: string };
}

const StatusTemplateLine: FunctionComponent<StatusTemplateLineProps> = ({
  node,
  dataColumns,
  paginationOptions,
}) => {
  const classes = useStyles();

  const data = useFragment(StatusTemplateLineFragment, node);

  return (
    <ListItemButton classes={{ root: classes.item }} divider={true}>
      <ListItemIcon style={{ color: data.color }}>
        <FactCheckOutlined />
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
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.usages.width }}
            >
              {data.usages}
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
