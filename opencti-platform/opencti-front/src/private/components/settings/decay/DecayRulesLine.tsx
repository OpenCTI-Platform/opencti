import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import Skeleton from '@mui/material/Skeleton';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { DecayRulesLine_node$key } from './__generated__/DecayRulesLine_node.graphql';

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

const decayRulesLineFragment = graphql`
  fragment DecayRulesLine_node on DecayRule {
    id
    name
    description
    created_at
    updated_at
    active
    order
    built_in
    appliedIndicatorsCount
  }
`;

interface DecayRulesLineProps {
  node: DecayRulesLine_node$key;
  dataColumns: DataColumns;
}

export const DecayRulesLine: FunctionComponent<DecayRulesLineProps> = ({
  node,
  dataColumns,
}) => {
  const classes = useStyles();
  const decayRule = useFragment(decayRulesLineFragment, node);
  return (
    <ListItemButton
      key={decayRule.id}
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`/dashboard/settings/customization/decay/${decayRule.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="DecayRule" />
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
                {value.render?.(decayRule)}
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

export const DecayRulesLineDummy = ({
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
