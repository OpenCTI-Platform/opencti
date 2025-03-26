import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { FactCheckOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import StatusTemplatePopover from './StatusTemplatePopover';
import { StatusTemplateLine_node$key } from './__generated__/StatusTemplateLine_node.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
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
});

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
    <ListItemButton classes={{ root: classes.item }}
      divider={true}
    >
      <ListItem
        secondaryAction={
          <StatusTemplatePopover
            statusTemplateId={data.id}
            paginationOptions={paginationOptions}
          />
        }
      >
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
      </ListItem>
    </ListItemButton>
  );
};

export default StatusTemplateLine;
