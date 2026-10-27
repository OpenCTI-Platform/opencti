import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router';
import { ListItemButton } from '@mui/material';
import { styled } from '@mui/material/styles';
import inject18n from '../../../../components/i18n';
import { groupsSearchQuery } from '../Groups';
import { QueryRenderer } from '../../../../relay/environment';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import DangerZoneChip from '../../common/danger_zone/DangerZoneChip';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const RoleLineComponent = ({ fd, dataColumns, node }) => {
  const { isSensitive } = useSensitiveModifications('roles', node.standard_id);

  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: '50px' }}
      divider={true}
      component={Link}
      to={`/dashboard/settings/accesses/roles/${node.id}`}
    >
      <ListItemText
        primary={(
          <>
            <BodyItem
              style={{
                width: dataColumns.name.width,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span>{node.name}</span>
              { isSensitive && <DangerZoneChip /> }
            </BodyItem>
            <QueryRenderer
              query={groupsSearchQuery}
              variables={{
                count: 50,
                orderBy: 'name',
                orderMode: 'asc',
              }}
              render={({ props }) => {
                if (props) {
                  const groupIds = props.groups.edges.map((group) => (group.node.roles.edges.map((role) => role.node.id).includes(node.id)
                    ? group.node.id
                    : null));
                  const numberOfGroups = groupIds.filter(
                    (id) => id !== null,
                  ).length;
                  return (
                    <BodyItem
                      style={{ width: dataColumns.groups.width }}
                    >
                      {numberOfGroups}
                    </BodyItem>
                  );
                }
                return (
                  <BodyItem
                    style={{ width: dataColumns.groups.width }}
                  >
                  </BodyItem>
                );
              }}
            />
            <BodyItem
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(node.created_at)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.updated_at.width }}
            >
              {fd(node.updated_at)}
            </BodyItem>
          </>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

RoleLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  fd: PropTypes.func,
};

const RoleLineFragment = createFragmentContainer(RoleLineComponent, {
  node: graphql`
    fragment RoleLine_node on Role {
      id
      standard_id
      name
      created_at
      updated_at
    }
  `,
});

export const RoleLine = inject18n(RoleLineFragment);

class RoleLineDummyComponent extends Component {
  render() {
    const { dataColumns } = this.props;
    return (
      <ListItem
        sx={{ paddingLeft: '10px', height: '50px' }}
        divider={true}
        secondaryAction={<KeyboardArrowRightOutlined />}
      >
        <ListItemIcon sx={{ color: (theme) => theme.palette.grey[700] }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              <BodyItem
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.groups.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.created_at.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.updated_at.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
            </div>
          )}
        />
      </ListItem>
    );
  }
}

RoleLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
};

export const RoleLineDummy = inject18n(RoleLineDummyComponent);
