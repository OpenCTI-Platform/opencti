import makeStyles from '@mui/styles/makeStyles';
import { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { ListItem, ListItemIcon, ListItemText, Skeleton } from '@mui/material';
import { Link } from 'react-router-dom';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';
import { AssetLine_node$key } from './__generated__/AssetLine_node.graphql';

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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

const assetLineFragment = graphql`
  fragment AssetLine_node on FinancialAsset {
    id
    name
    created
    modified
  }
`;

interface AssetLineComponentProps {
  dataColumns: DataColumns;
  node: AssetLine_node$key;
}

export const AssetLineComponent: FunctionComponent<AssetLineComponentProps> = ({ dataColumns, node }) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  const data = useFragment(assetLineFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`/dashboard/financial/assets/${data.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Financial-Asset" />
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

export const AssetLineDummy = () => {
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
