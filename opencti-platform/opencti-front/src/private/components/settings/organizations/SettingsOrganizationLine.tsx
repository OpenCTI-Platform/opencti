import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Skeleton from '@mui/material/Skeleton';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined, MoreVertOutlined } from '@mui/icons-material';
import { Link } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import { ListItemButton } from '@mui/material';
import Box from '@mui/material/Box';
import { styled } from '@mui/material/styles';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { SettingsOrganizationLine_node$key } from './__generated__/SettingsOrganizationLine_node.graphql';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

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
  }
`;

export const SettingsOrganizationLine: FunctionComponent<SettingsOrganizationLineProps> = ({
  node,
  dataColumns,
}) => {
  const { t_i18n } = useFormatter();

  const organization = useFragment(SettingsOrganizationFragment, node);
  return (
    <ListItemButton
      key={organization.id}
      sx={{ paddingLeft: '10px', height: '50px' }}
      divider={true}
      component={Link}
      to={`/dashboard/settings/accesses/organizations/${organization.id}`}
    >
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                {value.render?.(organization, { t: t_i18n })}
              </BodyItem>
            ))}
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const SettingsOrganizationLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: '50px' }}
      divider={true}
      secondaryAction={(
        <Box>
          <MoreVertOutlined />
        </Box>
      )}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.grey?.[700] }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
