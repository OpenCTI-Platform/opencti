import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import { LockPersonOutlined, NorthEastOutlined, ShortTextOutlined } from '@mui/icons-material';
import EEChip from '@components/common/entreprise_edition/EEChip';
import Box from '@mui/material/Box';
import { styled } from '@mui/material/styles';
import { DataColumns } from '../../../../../components/list_lines';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import EntitySettingAttributeEdition from './EntitySettingAttributeEdition';
import { EntitySettingAttributeLine_attribute$key } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$data } from './__generated__/EntitySettingAttributes_entitySetting.graphql';
import { INPUT_AUTHORIZED_MEMBERS } from '../../../../../utils/authorizedMembers';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';
import { bodyItemStyle } from '../../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const entitySettingAttributeLineFragment = graphql`
  fragment EntitySettingAttributeLine_attribute on TypeAttribute {
    name
    type
    label
    multiple
    mandatory
    mandatoryType
    editDefault
    defaultValues {
      id
      name
    }
    scale
  }
`;

interface EntitySettingAttributeLineProps {
  node?: EntitySettingAttributeLine_attribute$key;
  dataColumns?: DataColumns;
  entitySetting: EntitySettingAttributes_entitySetting$data;
}

const EntitySettingAttributeLine: FunctionComponent<EntitySettingAttributeLineProps> = ({ node = null, dataColumns, entitySetting }) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const attribute = useFragment(entitySettingAttributeLineFragment, node);

  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  if (!node || !attribute) {
    return <ErrorNotFound />;
  }

  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);

  const needEE = attribute.name === INPUT_AUTHORIZED_MEMBERS && !isEnterpriseEdition;
  const nothingToUpdate = attribute.mandatoryType !== 'customizable' && !attribute.editDefault;

  return (
    <>
      <ListItemButton
        key={attribute.name}
        divider={true}
        onClick={() => !needEE && !nothingToUpdate && handleOpenUpdate()}
        disableRipple={needEE || nothingToUpdate}
        sx={[
          { paddingLeft: '10px', height: '50px' },
          needEE || nothingToUpdate
            ? {
                '&:hover': {
                  cursor: 'default',
                  backgroundColor: 'transparent',
                },
              }
            : {},
        ]}
      >
        <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
          {attribute.name === INPUT_AUTHORIZED_MEMBERS
            ? (
                <LockPersonOutlined
                  fontSize="small"
                  color={!needEE ? 'warning' : 'ee'}
                />
              )
            : <ShortTextOutlined />
          }
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              {Object.values(dataColumns ?? {}).map((value, i) => (
                <BodyItem
                  key={value.label}
                  style={{ width: value.width }}
                >
                  {value.render?.(attribute)}
                  {needEE && i === 0 && <EEChip />}
                </BodyItem>
              ))}
            </div>
          )}
        />
        <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
          {!needEE && !nothingToUpdate && <NorthEastOutlined />}
        </ListItemIcon>
      </ListItemButton>
      <EntitySettingAttributeEdition
        attribute={attribute}
        entitySetting={entitySetting}
        handleClose={handleCloseUpdate}
        open={displayUpdate}
      />
    </>
  );
};

export default EntitySettingAttributeLine;

export const EntitySettingAttributeLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem
      divider={true}
      sx={{ paddingLeft: '10px', height: '50px' }}
      secondaryAction={(
        <Box>
          <NorthEastOutlined />
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
