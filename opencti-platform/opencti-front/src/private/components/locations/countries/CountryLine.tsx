import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined, FlagOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { CountryLine_node$key } from './__generated__/CountryLine_node.graphql';
import { DataColumns } from '../../../../components/list_lines';
import { APP_BASE_PATH } from '../../../../relay/environment';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
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
  text: {
    fontSize: 12,
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

interface CountryLineProps {
  dataColumns: DataColumns;
  node: CountryLine_node$key;
}

const countryLineFragment = graphql`
  fragment CountryLine_node on Country {
    id
    name
    x_opencti_aliases
    created
    modified
  }
`;

export const CountryLineComponent: FunctionComponent<CountryLineProps> = ({
  dataColumns,
  node,
}) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  const data = useFragment(countryLineFragment, node);
  const flag = R.head(
    (data.x_opencti_aliases ?? []).filter((n) => n?.length === 2),
  );
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/locations/countries/${data.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        {flag ? (
          <img
            style={{ width: 20 }}
            src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
            alt={data.name}
          />
        ) : (
          <FlagOutlined />
        )}
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
              style={{ width: dataColumns.created.width }}
            >
              {fd(data.created)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.modified.width }}
            >
              {fd(data.modified)}
            </div>
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export const CountryLineDummy = () => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div className={classes.name}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div className={classes.createdAt}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </div>
            <div className={classes.modifiedAt}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </div>
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
