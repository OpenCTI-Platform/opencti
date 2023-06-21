import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Skeleton from '@mui/material/Skeleton';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { KeyboardArrowRightOutlined, MoreVertOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import ItemIcon from '../../../../components/ItemIcon';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { SettingsOrganizationLine_node$key } from './__generated__/SettingsOrganizationLine_node.graphql';

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
    paddingRight: 10,
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

interface SettingsOrganizationLineProps {
  node: SettingsOrganizationLine_node$key;
  dataColumns: DataColumns;
}

const SettingsOrganizationFragment = graphql`
  fragment SettingsOrganizationLine_node on Organization {
    id
    x_opencti_organization_type
    name
    created
    modified
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
  }
`;

export const SettingsOrganizationLine: FunctionComponent<SettingsOrganizationLineProps> = ({
  node,
  dataColumns,
}) => {
  const classes = useStyles();
  const { fd, t } = useFormatter();

  const organization = useFragment(SettingsOrganizationFragment, node);
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/settings/accesses/organizations/${organization.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Organization" />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {organization.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.x_opencti_organization_type.width }}
            >
              {organization.x_opencti_organization_type
                ? t(`organization_${organization.x_opencti_organization_type}`)
                : ''}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={organization.objectLabel}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created.width }}
            >
              {fd(organization.created)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.modified.width }}
            >
              {fd(organization.modified)}
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

export const SettingsOrganizationLineDummy = ({
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
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <MoreVertOutlined />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
