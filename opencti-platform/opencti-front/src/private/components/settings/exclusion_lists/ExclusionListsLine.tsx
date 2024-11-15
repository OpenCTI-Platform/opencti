import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Skeleton from '@mui/material/Skeleton';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import ListItemButton from '@mui/material/ListItemButton';
import { Link } from 'react-router-dom';
import { ExclusionListsLine_node$key } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { Theme } from '../../../../components/Theme';
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
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
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
}));

const exclusionListsLineFragment = graphql`
  fragment ExclusionListsLine_node on ExclusionList {
    id
    name
    description
    created_at
    standard_id
    entity_type
    enabled
    file_id
  }
`;

interface ExclusionListsLineProps {
  node: ExclusionListsLine_node$key;
  dataColumns: DataColumns;
}

export const ExclusionListsLine: FunctionComponent<ExclusionListsLineProps> = ({
  node,
  dataColumns,
}) => {
  const classes = useStyles();
  const exclusionList = useFragment(exclusionListsLineFragment, node);
  return (
    <ListItemButton
      key={exclusionList.id}
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`/dashboard/settings/customization/decay/${exclusionList.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="ExclusionList" />
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
                {value.render?.(exclusionList)}
              </div>
            ))}
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const ExclusionListsLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
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
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined color="disabled" />
      </ListItemIcon>
    </ListItem>
  );
};
