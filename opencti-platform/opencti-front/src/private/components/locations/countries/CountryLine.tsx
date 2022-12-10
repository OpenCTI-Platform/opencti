import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined, FlagOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { CountryLine_node$key } from './__generated__/CountryLine_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {},
  itemIcon: {
    color: theme.palette.primary.main,
  },
  name: {
    width: '60%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  createdAt: {
    width: '20%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    color: '#a5a5a5',
  },
  modifiedAt: {
    width: '20%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    color: '#a5a5a5',
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
  node: CountryLine_node$key
}

const countryLineFragment = graphql`
  fragment CountryLine_node on Country {
    id
    name
    created
    modified
  }
`;

export const CountryLineComponent: FunctionComponent<CountryLineProps> = ({ node }) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  const data = useFragment(countryLineFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/locations/countries/${data.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <FlagOutlined />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div className={classes.name}>
              {data.name}
            </div>
            <div className={classes.createdAt}>
              {fd(data.created)}
            </div>
            <div className={classes.modifiedAt}>
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
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
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
