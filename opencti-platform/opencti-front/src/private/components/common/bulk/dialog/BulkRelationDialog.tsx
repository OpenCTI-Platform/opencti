import React, { FunctionComponent, useState, ChangeEvent, useEffect, useRef } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import BulkSelectRawLineData from '@components/common/bulk/BulkSelectRawLineData';
import { stixCoreRelationshipCreationFromEntityFromMutation, TargetEntity } from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import { commitMutation, fetchQuery, MESSAGING$ } from 'src/relay/environment';
import Typography from '@mui/material/Typography';
import { useFormatter } from 'src/components/i18n';
import useAuth from 'src/utils/hooks/useAuth';
import MenuItem from '@mui/material/MenuItem';
import { Alert, FormControl, FormHelperText, InputLabel, List, ListItem, Select, SelectChangeEvent } from '@mui/material';
import TextField from '@mui/material/TextField';
import Box from '@mui/material/Box';
import { StixCoreRelationshipAddInput } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipCreationMutation.graphql';
import Loader from 'src/components/Loader';
import { graphql } from 'react-relay';
import { ForceUpdateEvent } from '@components/common/bulk/useForceUpdate';
import BulkTextModalButton from 'src/components/fields/BulkTextField/BulkTextModalButton';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import { PaginationOptions } from 'src/components/list_lines';
import StixCyberObservableCreation from '@components/observations/stix_cyber_observables/StixCyberObservableCreation';
import { type StixCoreResultsType } from '../utils/querySearchEntityByText';
import { getRelationsFromOneEntityToAny, RelationsDataFromEntity, RelationsToEntity } from '../../../../../utils/Relation';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';
import { v4 as uuid } from 'uuid';

export const searchStixCoreObjectsByRepresentativeQuery = graphql`
  query BulkRelationDialogQuery(
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjects(types: $types, search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          objectLabel {
            id
            value
            color
          }
          creators {
            id
            name
          }
          containersNumber {
            total
          }
        }
      }
    }
  }
`;

interface BulkRelationDialogProps {
  stixDomainObjectId: string;
  stixDomainObjectName: string;
  stixDomainObjectType: string;
  isOpen: boolean;
  onClose: () => void;
  selectedEntities: TargetEntity[];
  defaultRelationshipType?: string;
  paginationKey: string;
  paginationOptions: PaginationOptions;
  targetObjectTypes: string[];
  onBulkCreate: () => void;
}

export interface BulkEntityTypeInfo {
  id: string;
  representative: string;
  searchTerm: string;
  entityName?: string;
  entityType?: string;
  index: number;
  isMatchingEntity: boolean;
  isExisting: boolean;
  selectedEntityType: RelationsToEntity;
  entityTypeList?: entityTypeListType[];
}

type entityTypeListType = {
  entity_type: string;
  representative: string;
  id: string;
};

type missingEntityType = {
  key: string;
  values: string[];
};

const querySearchEntityByText = async (text: string) => {
  const searchPaginationOptions = {
    filters: {
      mode: 'and',
      filters: [
        {
          key: 'bulkSearchKeywords',
          values: [text],
        },
      ],
      filterGroups: [],
    },
    count: 1,
  };

  const result = await fetchQuery(
    searchStixCoreObjectsByRepresentativeQuery,
    searchPaginationOptions,
  ).toPromise()
    .then((data) => {
      return data;
    }) as StixCoreResultsType;
  return { ...result, searchTerm: text };
};

export const toHeaderWidth = 180;
export const entityTypeHeaderWidth = 180;
export const entityNameHeaderWidth = 180;
export const matchHeaderWidth = 250;

const EntityTypeWithoutBulkEntityCreation = [
  'Attack-Pattern',
  'Course-of-Action',
  'Feedback',
  'Grouping',
  'Incident',
  'Malware-Analysis',
  'Note',
  'Report',
  'Opinion',
  'Position',
];

const BulkRelationDialog: FunctionComponent<BulkRelationDialogProps> = ({
  stixDomainObjectId,
  stixDomainObjectType,
  stixDomainObjectName,
  isOpen,
  onClose,
  selectedEntities,
  defaultRelationshipType,
  paginationKey,
  paginationOptions,
  targetObjectTypes,
  onBulkCreate,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [textAreaValue, setTextAreaValue] = useState<string[]>([...selectedEntities.map((item) => item.name ?? '')]);
  const [entityToSearch, setEntityToSearch] = useState<string[]>([]);
  const [bulkEntityList, setBulkEntityList] = useState<BulkEntityTypeInfo[]>([]);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [isObjectCreationFormOpen, setIsObjectCreationFormOpen] = useState<boolean>(false);
  const [missingEntity, setMissingEntity] = useState<missingEntityType>();
  const [isFirstLoadDone, setIsFirstLoadDone] = useState<boolean>(false);

  const textRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const timeoutId = setTimeout(() => {
      const newEntityToSearch = [...textAreaValue];
      if (newEntityToSearch.length && newEntityToSearch[newEntityToSearch.length - 1] === '') newEntityToSearch.pop();
      setEntityToSearch([...newEntityToSearch]);
    }, 500);
    return () => clearTimeout(timeoutId);
  }, [textAreaValue, 500]);

  const { schema } = useAuth();
  const scoLabelList = schema.scos.map(({ label }) => label);
  const resolvedRelations: RelationsDataFromEntity = getRelationsFromOneEntityToAny(stixDomainObjectType, schema);
  const entityList = resolvedRelations.allRelationsToEntity;
  const relationListArray = resolvedRelations.allPossibleRelations;

  const getDefaultSelectedRelationshipType = () => {
    if (defaultRelationshipType && relationListArray.includes(defaultRelationshipType.toLowerCase())) {
      return defaultRelationshipType.toLowerCase();
    }
    return relationListArray[0];
  };

  const [selectedRelationType, setSelectedRelationType] = useState<string>(getDefaultSelectedRelationshipType());

  const getRelationMatchStatus = (selectedEntityType: RelationsToEntity, entityTypeList: entityTypeListType[]): boolean => {
    const matchingEntity = entityTypeList?.find((foundEntity) => foundEntity.entity_type === selectedEntityType?.toEntitytype);
    return !!(selectedEntityType?.legitRelations.includes(selectedRelationType) && matchingEntity);
  };

  const selectMissingEntities = (currentBulkEntityList: BulkEntityTypeInfo[]) => {
    const foundMissingEntity = currentBulkEntityList.find((item) => !item.isExisting && item.selectedEntityType.legitRelations.includes(selectedRelationType));
    if (!foundMissingEntity) {
      if (missingEntity) setMissingEntity(undefined);
      return;
    }
    if (EntityTypeWithoutBulkEntityCreation.includes(foundMissingEntity.selectedEntityType.toEntitytype)) {
      setMissingEntity({
        key: foundMissingEntity.selectedEntityType.toEntitytype,
        values: [foundMissingEntity.searchTerm],
      });
    } else {
      const { selectedEntityType: { toEntitytype } } = foundMissingEntity;
      setMissingEntity({
        key: toEntitytype,
        values: currentBulkEntityList
          .filter((item) => item.selectedEntityType.toEntitytype === toEntitytype && !item.isExisting)
          .map((item) => item.searchTerm),
      });
    }
  };

  useEffect(() => {
    selectMissingEntities(bulkEntityList);
  }, [bulkEntityList]);

  const getDefaultEntityType = () => {
    if (targetObjectTypes.length === 1 && targetObjectTypes.includes('Threat-Actor')) {
      const foundThreatActor = entityList
        .filter((item) => item.toEntitytype.includes('Threat-Actor'))
        .sort((a, b) => (a.toEntitytype < b.toEntitytype ? -1 : 1))[0];
      return foundThreatActor ?? entityList[0];
    }
    if (targetObjectTypes.length === 1 && targetObjectTypes.includes('Stix-Cyber-Observable')) {
      const foundObservableType = entityList
        .filter((obs) => obs.isObservable)
        .sort((a, b) => (a.toEntitytype < b.toEntitytype ? -1 : 1))[0];
      return foundObservableType ?? entityList[0];
    }
    const selectedEntityType = targetObjectTypes[0];
    const foundEntityType = entityList.find((item) => item.toEntitytype === selectedEntityType);
    return foundEntityType ?? entityList[0];
  };

  useEffect(() => {
    const getBulkEntities = async () => {
      const rawLinesPromises: Promise<StixCoreResultsType>[] = entityToSearch.map((content) => querySearchEntityByText(content));
      const resultsAwait: StixCoreResultsType[] = await Promise.all(rawLinesPromises);
      const newBulkEntityList = resultsAwait.reduce((acc: BulkEntityTypeInfo[], cur: StixCoreResultsType, index: number) => {
        const foundItem = bulkEntityList.find((item) => item.searchTerm === cur.searchTerm);
        const defaultEntityType = getDefaultEntityType();
        if (cur.stixCoreObjects.edges.length > 0) {
          const { edges } = cur.stixCoreObjects;

          const currentStixObject = foundItem
            ? edges.find((item) => item.node.entity_type === foundItem.selectedEntityType.toEntitytype)?.node
            : edges[0].node;
          const entityTypeList = edges.map(({ node }) => ({
            entity_type: node.entity_type,
            representative: node.representative.main,
            id: node.id,
          }));

          const foundEntityType = entityList.filter((entityType) => entityType.toEntitytype === entityTypeList[0].entity_type);
          const newSelectedEntityType: RelationsToEntity = foundEntityType.length ? foundEntityType[0] : entityList[0];

          let selectedEntityType: RelationsToEntity = (foundItem && foundItem.selectedEntityType) ?? newSelectedEntityType;

          const isExisting = foundItem ? !!entityTypeList.find((item) => item.entity_type === selectedEntityType.toEntitytype) : true;
          const isMatchingEntity = getRelationMatchStatus(selectedEntityType, entityTypeList);

          const foundSelectedItem = selectedEntities.find((item) => item.name === cur.searchTerm);

          if (!isFirstLoadDone) {
            const selectedEntityTypeFromSelectedEntity = entityList.find((item) => item.toEntitytype === foundSelectedItem?.entity_type);
            if (selectedEntityTypeFromSelectedEntity) selectedEntityType = selectedEntityTypeFromSelectedEntity;
            setIsFirstLoadDone(true);
          }
          return [...acc, {
            id: uuid(),
            representative: currentStixObject?.representative.main ?? foundItem?.representative ?? cur.searchTerm,
            entityTypeList,
            isMatchingEntity,
            isExisting,
            selectedEntityType,
            index,
            searchTerm: cur.searchTerm,
          }];
        }
        return [...acc, {
          id: uuid(),
          isExisting: false,
          representative: foundItem?.representative ?? cur.searchTerm,
          selectedEntityType: foundItem?.selectedEntityType ?? defaultEntityType,
          index,
          isMatchingEntity: false,
          searchTerm: cur.searchTerm,
        }];
      }, []);
      setBulkEntityList([...newBulkEntityList]);
    };
    getBulkEntities().catch(() => false);
  }, [entityToSearch]);

  useEffect(() => {
    const bulkEntityListToEdit = bulkEntityList.map((item) => {
      const { selectedEntityType, entityTypeList } = item;
      return {
        ...item,
        isMatchingEntity: getRelationMatchStatus(selectedEntityType, entityTypeList ?? []),
      };
    });
    setBulkEntityList([...bulkEntityListToEdit]);
  }, [selectedRelationType]);
  const handleChangeSelectedRelationType = (event: SelectChangeEvent) => {
    setSelectedRelationType(event.target.value);
  };

  const handleChangeTextArea = async (event: ChangeEvent<HTMLTextAreaElement>) => {
    const rawLines: string[] = event.target.value.split(/\r?\n/);
    if (rawLines.length === 1 && rawLines[0] === '') {
      setTextAreaValue([]);
      return;
    }
    setTextAreaValue([...rawLines]);
  };

  const onDeleteEntity = (entityIndex: number) => {
    const filteredBulkEntityList = bulkEntityList.filter((_, index) => index !== entityIndex);
    const filteredTextAreaValue = textAreaValue.filter((_, index) => index !== entityIndex);
    setBulkEntityList([...filteredBulkEntityList]);
    setTextAreaValue([...filteredTextAreaValue]);
    textRef.current?.focus();
  };

  const onChangeEntityType = (value: RelationsToEntity, entityIndex: number) => {
    const bulkEntityListToEdit = bulkEntityList;
    const { entityTypeList } = bulkEntityListToEdit[entityIndex];
    const foundEntityType = (entityTypeList ?? []).find((item) => item.entity_type === value.toEntitytype);
    if (foundEntityType) {
      bulkEntityListToEdit[entityIndex].representative = foundEntityType.representative;
      bulkEntityListToEdit[entityIndex].isExisting = true;
    }
    if (!foundEntityType) {
      bulkEntityListToEdit[entityIndex].isExisting = false;
      bulkEntityListToEdit[entityIndex].representative = bulkEntityListToEdit[entityIndex].searchTerm;
    }
    bulkEntityListToEdit[entityIndex].selectedEntityType = value;
    bulkEntityListToEdit[entityIndex].isMatchingEntity = getRelationMatchStatus(value, entityTypeList ?? []);
    setBulkEntityList([...bulkEntityListToEdit]);
    selectMissingEntities(bulkEntityListToEdit);
  };

  const handleOpenObjectCreateEntityForm = () => setIsObjectCreationFormOpen(true);

  const handleRefreshBulkEntityList = () => {
    setEntityToSearch([...entityToSearch]);
  };

  const handleCloseObjectCreateEntityForm = () => setIsObjectCreationFormOpen(false);

  const onCompletedObjectCreation = () => {
    handleRefreshBulkEntityList();
    handleCloseObjectCreateEntityForm();
  };

  const commit = (finalValues: StixCoreRelationshipAddInput) => {
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: stixCoreRelationshipCreationFromEntityFromMutation,
        variables: { input: finalValues },
        optimisticUpdater: undefined,
        setSubmitting: undefined,
        optimisticResponse: undefined,
        updater: undefined,
        onError: (error: Error) => {
          reject(error);
        },
        onCompleted: (response: Response) => {
          resolve(response);
        },
      });
    });
  };

  const handleSubmit = async () => {
    setIsSubmitting(true);
    for (const bulkEntity of bulkEntityList) {
      const foundEntityType = bulkEntity.entityTypeList && bulkEntity.entityTypeList.find((entity) => entity.entity_type === bulkEntity.selectedEntityType.toEntitytype);
      if (!foundEntityType) return;
      const finalValues = {
        relationship_type: selectedRelationType,
        fromId: stixDomainObjectId,
        toId: foundEntityType.id,
      };
      try {
        await commit(finalValues);
      } catch (error) {
        MESSAGING$.notifyRelayError(error);
        setIsSubmitting(false);
      }
    }
    setIsSubmitting(false);
    onClose();
    onBulkCreate();
    dispatchEvent(new CustomEvent(ForceUpdateEvent));
  };
  const getTextAreaValue = () => textAreaValue.join('\n');
  const isSubmitDisable = !bulkEntityList.every((item) => item.isMatchingEntity) || bulkEntityList.length === 0;

  const renderLoader = () => (
    <Box sx={{ width: '100%', height: '100%', backgroundColor: '#000000', opacity: 0.5, position: 'absolute' }}>
      <Loader />
    </Box>
  );

  const renderStixDomainObjectCreationForm = () => {
    if (!isObjectCreationFormOpen || !missingEntity) return null;

    if (scoLabelList.includes(missingEntity.key)) {
      return (
        <StixCyberObservableCreation
          paginationOptions={paginationOptions}
          open={isObjectCreationFormOpen}
          speeddial={isObjectCreationFormOpen}
          onCompleted={onCompletedObjectCreation}
          inputValue={missingEntity.values?.join('\n') ?? ''}
          display={isObjectCreationFormOpen}
          paginationKey={paginationKey}
          handleClose={handleCloseObjectCreateEntityForm}
          type={missingEntity.key}
          contextual={true}
          isFromBulkRelation
          defaultCreatedBy={undefined}
        />
      );
    }
    return (
      <StixDomainObjectCreation
        paginationOptions={paginationOptions}
        onCompleted={onCompletedObjectCreation}
        open={isObjectCreationFormOpen}
        speeddial={isObjectCreationFormOpen}
        inputValue={missingEntity.values?.join('\n') ?? ''}
        display={isObjectCreationFormOpen}
        paginationKey={paginationKey}
        stixDomainObjectTypes={missingEntity.key}
        handleClose={handleCloseObjectCreateEntityForm}
        confidence={undefined}
        defaultCreatedBy={undefined}
        creationCallback={undefined}
        defaultMarkingDefinitions={undefined}
        isFromBulkRelation
      />
    );
  };

  return (
    <>
      <Dialog open={isOpen} onClose={onClose} fullWidth maxWidth="md">
        {isSubmitting && renderLoader()}
        <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', height: '70px' }}>
          <div>{t_i18n('Create relations in bulk')}</div>
        </DialogTitle>

        <DialogContent id="container" sx={{ height: '80vh' }}>
          <Box component="form" sx={{ display: 'flex', height: '100%', width: '100%', minHeight: 350, flexDirection: 'column', gap: 4 }}>
            <Box>
              <Typography variant="body1">{t_i18n('Relationships will be created from the')} {t_i18n(`entity_${stixDomainObjectType}`)}: </Typography>
              <Typography variant="body2">{stixDomainObjectName}</Typography>
            </Box>
            {/* Relationship Type */}
            <Box>
              <FormControl fullWidth>
                <InputLabel id="bulk-relationship-create-relation-type-label">{t_i18n('Relationship type')}</InputLabel>
                <Select
                  labelId="bulk-relationship-create-relation-type-label"
                  id="bulk-relationship-create-relation-type-select"
                  aria-describedby="bulk-relation-create-relation-type-helper"
                  disabled={isSubmitting}
                  onChange={handleChangeSelectedRelationType}
                  value={selectedRelationType}
                >
                  {relationListArray.sort((a, b) => (t_i18n(`relationship_${a}`) < t_i18n(`relationship_${b}`) ? -1 : 1)).map((relation) => (
                    <MenuItem key={relation} value={relation}>
                      {t_i18n(`relationship_${relation}`)}
                    </MenuItem>
                  ))}
                </Select>
                <FormHelperText id="bulk-relation-create-relation-type-helper">{t_i18n('The relationship type to apply to all created relationships.')}</FormHelperText>
              </FormControl>
            </Box>
            {/* To */}
            <Box>
              <FormControl fullWidth>
                <TextField
                  id="bulk-relation-create-to-text-area"
                  disabled={isSubmitting}
                  aria-describedby="bulk-relation-create-to-helper"
                  sx={{
                    '.MuiInputBase-root': {
                      paddingTop: '2px',
                    },
                    '& .MuiInputBase-input': {
                      whiteSpace: textAreaValue.length ? 'nowrap' : 'wrap',
                    },
                  }}
                  label={t_i18n('To')}
                  value={getTextAreaValue()}
                  onChange={handleChangeTextArea}
                  multiline
                  rows={5}
                  variant="outlined"
                  slotProps={{
                    input: {
                      'aria-describedby': 'bulk-relation-create-to-helper',
                    },
                  }}
                  inputRef={textRef}
                />
                <FormHelperText id="bulk-relation-create-to-helper">{t_i18n('Type or copy paste data. Each entity should be on a new line.')}</FormHelperText>
              </FormControl>
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <BulkTextModalButton disabled={!missingEntity} title={t_i18n('Create missing entities')} onClick={handleOpenObjectCreateEntityForm} />
              {missingEntity ? <Alert severity="warning" sx={{ py: 0 }}>{t_i18n('Create entities before submitting.')}</Alert> : undefined}
            </Box>

            {/* Created entities */}
            <Box sx={{
              width: '100%',
              flex: 1,
              p: 1,
              minHeight: '100px',
              overflowY: 'scroll',
              background: theme.palette.background.accent,
              border: `1px solid ${theme.palette.border.main}`,
            }}
            >
              {bulkEntityList.length > 0 ? (
                <List disablePadding sx={{ height: '100%' }}>
                  {bulkEntityList.map((entity: BulkEntityTypeInfo, index) => {
                    return (
                      <ListItem
                        sx={{
                          width: '100%',
                          padding: 2,
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          border: `1px solid ${theme.palette.primary.dark}`,
                          backgroundColor: theme.palette.background.paper,
                          borderRadius: 0.5,
                          mt: 0.5,
                          mb: 0.5,
                          ':focus': {
                            border: `1px solid ${theme.palette.primary.main}`,
                          },
                        }}
                        key={entity.id}
                        disablePadding
                        tabIndex={0}
                      >
                        <BulkSelectRawLineData
                          entity={entity}
                          entityIndex={index}
                          selectedRelationType={selectedRelationType}
                          onChangeEntityType={onChangeEntityType}
                          onDeleteEntity={onDeleteEntity}
                          entityList={entityList}
                          isSubmitting={isSubmitting}
                        />
                      </ListItem>
                    );
                  })}
                </List>
              )
                : (
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', width: '100%' }}>
                      <Typography variant="body1">{t_i18n('Add to the text field to view created relationships.')}</Typography>
                    </Box>
                  )}
            </Box>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 2, pt: 0, mt: 0 }}>
          <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleSubmit} disabled={isSubmitDisable || isSubmitting}>
            {t_i18n('Create')}
          </Button>
        </DialogActions>
      </Dialog>
      {renderStixDomainObjectCreationForm()}
    </>
  );
};

export default BulkRelationDialog;
