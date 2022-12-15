import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { KeyboardArrowRightOutlined, LanguageOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { ExternalReferenceLine_node$data } from './__generated__/ExternalReferenceLine_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'pointer',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
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

interface ExternalReferenceLineComponentProps {
  dataColumns?: {
    source_name: {
      label: string, width: string, isSortable: boolean
    },
    external_id: {
      label: string, width: string, isSortable: boolean
    },
    url: {
      label: string, width: string, isSortable: boolean
    },
    created: {
      label: string,
      width: string,
      isSortable: boolean,
    }
  },
  node?: ExternalReferenceLine_node$data,
}

const ExternalReferenceLineComponent: FunctionComponent<ExternalReferenceLineComponentProps> = ({ dataColumns, node }) => {
  const classes = useStyles();
  const { fd } = useFormatter();

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/analysis/external_references/${node?.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <LanguageOutlined />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns?.source_name.width }}
            >
              {node?.source_name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns?.external_id.width }}
            >
              {node?.external_id}
            </div>
            <Tooltip title={node?.url}>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns?.url.width }}
              >
                {node?.url}
              </div>
            </Tooltip>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns?.created.width }}
            >
              {fd(node?.created)}
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <KeyboardArrowRightOutlined />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

const ExternalReferenceLineFragment = createFragmentContainer(
  ExternalReferenceLineComponent,
  {
    node: graphql`
      fragment ExternalReferenceLine_node on ExternalReference {
        id
        source_name
        external_id
        url
        created
      }
    `,
  },
);

export const ExternalReferenceLine = ExternalReferenceLineFragment;

interface ExternalReferenceLineDummyComponentProps {
  dataColumns?: {
    source_name: {
      label: string, width: string, isSortable: boolean
    },
    external_id: {
      label: string, width: string, isSortable: boolean
    },
    url: {
      label: string, width: string, isSortable: boolean
    },
    created: {
      label: string,
      width: string,
      isSortable: boolean,
    }
  },
}

const ExternalReferenceLineDummyComponent: FunctionComponent<ExternalReferenceLineDummyComponentProps> = ({ dataColumns }) => {
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
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns?.source_name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns?.external_id.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns?.url.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns?.created.width }}
            >
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
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <KeyboardArrowRightOutlined />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const ExternalReferenceLineDummy = ExternalReferenceLineDummyComponent;
