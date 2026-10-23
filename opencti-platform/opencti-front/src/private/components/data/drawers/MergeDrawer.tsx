import React from 'react';
import Alert from '@mui/material/Alert';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { Chip } from '@filigran/design-system';
// fds:keep-mui moved unchanged from DataTableToolBar.jsx by the toolbar refactoring, the conversion is left to the design-system migration
import Radio from '@mui/material/Radio';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { useFormatter } from '../../../../components/i18n';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { EMPTY_VALUE, truncate } from '../../../../utils/String';
import { computeMergePreview, type MergeElement } from './mergeDrawer.utils';

interface MergeDrawerProps {
  open: boolean;
  onClose: () => void;
  elements: MergeElement[];
  keptEntityId: string | null;
  onKeptEntityIdChange: (entityId: string) => void;
  onLaunch: (keptElement: MergeElement | undefined, mergedElements: MergeElement[]) => void;
  noAuthor?: boolean;
  noMarking?: boolean;
  noWarning?: boolean;
}

const MergeDrawer = ({
  open,
  onClose,
  elements,
  keptEntityId,
  onKeptEntityIdChange,
  onLaunch,
  noAuthor,
  noMarking,
  noWarning,
}: MergeDrawerProps) => {
  const { t_i18n } = useFormatter();
  const { keptElement, mergedElements, newAliases } = computeMergePreview(elements, keptEntityId);

  const subtitle = (text: string) => (
    <Typography
      variant="h3"
      gutterBottom={true}
      style={{ marginTop: 20 }}
    >
      {text}
    </Typography>
  );

  return (
    <Drawer
      title={t_i18n('Merge entities')}
      open={open}
      onClose={onClose}
    >
      <div>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Selected entities')}
        </Typography>
        <List>
          {elements.map((element) => (
            <ListItem
              key={element.id}
              dense={true}
              divider={true}
              secondaryAction={(
                <Radio
                  checked={keptEntityId ? keptEntityId === element.id : elements[0]?.id === element.id}
                  onChange={() => onKeptEntityIdChange(element.id)}
                  value={element.id}
                  name="keptEntityID"
                  inputProps={{ 'aria-label': 'keptEntityID' }}
                />
              )}
            >
              <ListItemIcon>
                <ItemIcon type={element.entity_type} />
              </ListItemIcon>
              <ListItemText
                sx={{
                  '.MuiListItemText-primary': {
                    overflowX: 'hidden',
                    textOverflow: 'ellipsis',
                  },
                }}
                primary={getMainRepresentative(element)}
                secondary={truncate(
                  element.description
                  || element.x_opencti_description
                  || '',
                  60,
                )}
              />
              <div style={{ marginRight: 50 }}>
                {element.createdBy?.name ?? EMPTY_VALUE}
              </div>
              <div style={{ marginRight: 50 }}>
                <ItemMarkings markingDefinitions={element.objectMarking ?? []} />
              </div>
            </ListItem>
          ))}
        </List>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t_i18n('Merged entity')}
        </Typography>
        {subtitle(t_i18n('Name'))}
        <div style={{ overflowX: 'hidden', textOverflow: 'ellipsis' }}>
          {getMainRepresentative(keptElement)}
        </div>
        {subtitle(t_i18n('Aliases'))}
        {newAliases.map((label) => (
          <Chip key={label} label={label} />
        ))}
        {noAuthor !== true && (
          <>
            {subtitle(t_i18n('Author'))}
            {keptElement?.createdBy?.name ?? EMPTY_VALUE}
          </>
        )}
        {noMarking !== true && (
          <>
            {subtitle(t_i18n('Marking'))}
            <ItemMarkings markingDefinitions={keptElement?.objectMarking ?? []} />
          </>
        )}
        {noWarning !== true && (
          <Alert severity="warning" style={{ marginTop: 20 }}>
            {t_i18n('The relations attached to selected entities will be copied to the merged entity.')}
          </Alert>
        )}
        <FormButtonContainer>
          <Button onClick={() => onLaunch(keptElement, mergedElements)}>
            {t_i18n('Merge')}
          </Button>
        </FormButtonContainer>
      </div>
    </Drawer>
  );
};

export default MergeDrawer;
