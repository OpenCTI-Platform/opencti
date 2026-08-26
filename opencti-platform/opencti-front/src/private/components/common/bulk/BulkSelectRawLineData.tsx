import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import { BulkEntityTypeInfo } from '@components/common/bulk/dialog/BulkRelationDialog';
import { DeleteOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { Autocomplete } from '@mui/material';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import { RelationsToEntity } from '../../../../utils/Relation';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

interface BulkSelectRawLineDataProps {
  entity: BulkEntityTypeInfo;
  entityIndex: number;
  entityList: RelationsToEntity[];
  isSubmitting: boolean;
  onChangeEntityType: (value: RelationsToEntity, entityIndex: number) => void;
  onDeleteEntity: (entityIndex: number) => void;
  selectedRelationType: string;
}

type autocompleteOptionsType = {
  label: string;
  value: RelationsToEntity;
  groupLabel: string;
  groupOrder: number;
};

const BulkSelectRawLineData: FunctionComponent<BulkSelectRawLineDataProps> = ({
  entity,
  entityIndex,
  entityList,
  selectedRelationType,
  onChangeEntityType,
  onDeleteEntity,
  isSubmitting,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isSearchTermEmpty = entity.searchTerm === '';
  const isMatchingRelationship = entity.selectedEntityType.legitRelations.includes(selectedRelationType);

  const getRelationMatchStatus = () => {
    if (!entity.isExisting && isMatchingRelationship) return t_i18n('Not in platform (compatible)');
    if (entity.isMatchingEntity && isMatchingRelationship) return t_i18n('Found (compatible)');
    return t_i18n('Incompatible');
  };

  const getChipColor = () => {
    if (!entity.isExisting && isMatchingRelationship) return 'error';
    if (entity.isMatchingEntity && isMatchingRelationship) {
      return 'success';
    }
    return 'warning';
  };

  const handleChangeEntityType = (newEntityType: string) => {
    const foundEntityType = entityList.find((entityType) => entityType.toEntitytype === newEntityType);
    if (foundEntityType) onChangeEntityType(foundEntityType, entityIndex);
  };

  const handleDeleteEntity = () => onDeleteEntity(entityIndex);

  const getAutocompleteOptions = () => {
    const possibleEntityTypes = entity.entityTypeList?.map((item) => item.entity_type) ?? [];
    return entityList.reduce((acc: autocompleteOptionsType[], cur) => {
      if (!acc.find((item) => item.label === t_i18n(`entity_${cur.toEntitytype}`))) {
        const isSuggestion = possibleEntityTypes.includes(cur.toEntitytype) && cur.legitRelations.includes(selectedRelationType);
        return [...acc, {
          label: t_i18n(`entity_${cur.toEntitytype}`),
          value: cur,
          groupLabel: isSuggestion ? t_i18n('Suggestions') : t_i18n('Entity list'),
          groupOrder: isSuggestion ? 0 : 1,
        }];
      }
      return [...acc];
    }, [])
      .sort((a, b) => (a.label < b.label ? -1 : 1))
      .sort((a, b) => a.groupOrder - b.groupOrder);
  };

  const getAutocompleteValue = () => {
    const autocompleteOptions = getAutocompleteOptions();
    return autocompleteOptions.find((option) => option.value.toEntitytype === entity.selectedEntityType.toEntitytype);
  };

  return (
    <>
      <Box>
        <Autocomplete
          autoHighlight
          disableClearable
          disabled={isSearchTermEmpty || isSubmitting}
          noOptionsText={t_i18n('No available options')}
          options={getAutocompleteOptions()}
          onChange={(event, selectedOption) => {
            handleChangeEntityType(selectedOption.value.toEntitytype);
          }}
          value={getAutocompleteValue()}
          groupBy={(option) => option.groupLabel}
          sx={{ borderBottom: 'none' }}
          renderInput={(params) => (
            <TextField
              label={t_i18n('Entity type')}
              sx={{ minWidth: '150px' }}
              {...params}
            />
          )}
        />
      </Box>
      <Box
        tabIndex={0}
        sx={{
          '&:focus-visible': {
            boxShadow: `0 0 0 2px ${theme.palette.text.primary}`,
          },
        }}
      >
        <Typography variant="body1" id={`representation-label-${entityIndex}`}>{t_i18n('Representation')}</Typography>
        <Typography
          sx={{
            fontSize: '0.9rem',
            height: '32px',
            margin: 0,
            display: 'flex',
            alignItems: 'center',
          }}
          variant="body2"
        >
          {truncate(isSearchTermEmpty ? entity.searchTerm : entity.representative, 20)}
        </Typography>
      </Box>
      <Box
        tabIndex={0}
        sx={{
          display: 'flex', flexDirection: 'column', '&:focus-visible': {
            boxShadow: `0 0 0 2px ${theme.palette.text.primary}`,
          },
        }}
      >
        <Typography variant="body1" id={`match-status-label-${entityIndex}`}>{t_i18n('Relationship match status')}</Typography>
        <Chip
          variant="outlined"
          sx={{ borderRadius: '4px' }}
          label={getRelationMatchStatus()}
          color={getChipColor()}
        />
      </Box>
      <Box>
        <IconButton
          aria-label={t_i18n('Delete entity')}
          disabled={isSubmitting}
          key={`${entity.representative}`}
          size="small"
          sx={{ height: '28px', width: '28px' }}
          onClick={handleDeleteEntity}
        >
          <DeleteOutlined />
        </IconButton>
      </Box>
    </>
  );
};

export default BulkSelectRawLineData;
