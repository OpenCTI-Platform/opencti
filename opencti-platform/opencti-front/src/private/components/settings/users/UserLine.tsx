import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { PersonOutlined, AccountCircleOutlined, KeyboardArrowRightOutlined, HorizontalRule, Security, ReportGmailerrorred, ManageAccountsOutlined } from '@mui/icons-material';
import { Link } from 'react-router';
import { styled } from '@mui/material/styles';
import { UserLine_node$data } from '@components/settings/users/__generated__/UserLine_node.graphql';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface UserLineComponentProps {
  dataColumns: DataColumns;
  node: UserLine_node$data;
}

const UserLineComponent: React.FC<UserLineComponentProps> = (props) => {
  const { dataColumns, node } = props;
  const external = node.external === true;
  const userServiceAccount = node.user_service_account;
  const { t_i18n, fd } = useFormatter();
  const passwordValidUntil = (node as { password_valid_until?: string | null }).password_valid_until;
  const passwordValidUntilDisplay = dataColumns.password_valid_until
    ? (dataColumns.password_valid_until.render
        ? dataColumns.password_valid_until.render(passwordValidUntil)
        : (passwordValidUntil ? fd(passwordValidUntil) : '-'))
    : null;

  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={`/dashboard/settings/accesses/users/${node.id}`}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        {userServiceAccount && (<ManageAccountsOutlined />)}
        {!userServiceAccount && (external ? <AccountCircleOutlined /> : <PersonOutlined />)}
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {node.name}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.user_email.width }}
            >
              {node.user_email}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.firstname.width }}
            >
              <FieldOrEmpty source={node.firstname}>{node.firstname}</FieldOrEmpty>
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.lastname.width }}
            >
              <FieldOrEmpty source={node.lastname}>{node.lastname}</FieldOrEmpty>
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.effective_confidence_level.width }}
            >
              {node.effective_confidence_level?.max_confidence ?? (
                <Tooltip
                  title={t_i18n("No confidence level found in this user's groups, and no confidence level defined at the user level.")}
                >
                  <ReportGmailerrorred fontSize="small" color="error" />
                </Tooltip>
              )}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.otp.width }}
            >
              {node.otp_activated ? (
                <Security fontSize="small" color="secondary" />
              ) : (
                <HorizontalRule fontSize="small" color="primary" />
              )}
            </BodyItem>
            {dataColumns.password_valid_until && (
              <BodyItem
                style={{ width: dataColumns.password_valid_until.width }}
              >
                {passwordValidUntilDisplay}
              </BodyItem>
            )}
            <BodyItem
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(node.created_at)}
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const UserLine = createFragmentContainer(UserLineComponent, {
  node: graphql`
    fragment UserLine_node on User {
      id
      entity_type
      name
      user_service_account
      user_email
      firstname
      external
      lastname
      effective_confidence_level {
        max_confidence 
      }
      otp_activated
      password_valid_until
      created_at
    }
  `,
});

export const UserLineDummy: React.FC<Pick<UserLineComponentProps, 'dataColumns'>> = (props) => {
  const { dataColumns } = props;

  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
      <ListItemIcon sx={{ color: (theme) => theme.palette.grey?.[700] }}>
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
              style={{ width: dataColumns.user_email.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.firstname.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.lastname.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.effective_confidence_level.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.otp.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={40}
                height="100%"
              />
            </BodyItem>
            {dataColumns.password_valid_until
              && (
                <BodyItem
                  style={{ width: dataColumns.password_valid_until.width }}
                >
                  <Skeleton
                    animation="wave"
                    variant="rectangular"
                    width={100}
                    height="100%"
                  />
                </BodyItem>
              )}
            <BodyItem
              style={{ width: dataColumns.created_at.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
