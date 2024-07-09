import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader, UseQueryLoaderLoadQueryOptions } from 'react-relay';
import Grid from '@mui/material/Grid';
import StixCoreObjectMappableContent from '@components/common/stix_core_objects/StixCoreObjectMappableContent';
import Paper from '@mui/material/Paper';
import { Link } from 'react-router-dom';
import { containerContentFragment, contentMutationFieldPatch } from '@components/common/containers/ContainerContent';
import ContainerStixCoreObjectsSuggestedMapping, { containerStixCoreObjectsSuggestedMappingQuery } from '@components/common/containers/ContainerStixCoreObjectsSuggestedMapping';
import {
  ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation,
} from '@components/common/containers/__generated__/ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation.graphql';
import { ContainerContentFieldPatchMutation } from '@components/common/containers/__generated__/ContainerContentFieldPatchMutation.graphql';
import {
  ContainerStixCoreObjectsSuggestedMappingQuery,
  ContainerStixCoreObjectsSuggestedMappingQuery$data,
  ContainerStixCoreObjectsSuggestedMappingQuery$variables,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import { ContainerContent_container$data, ContainerContent_container$key } from '@components/common/containers/__generated__/ContainerContent_container.graphql';
import { ContainerContentQuery$data } from '@components/common/containers/__generated__/ContainerContentQuery.graphql';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import ContainerStixCoreObjectsMapping from '@components/common/containers/ContainerStixCoreObjectsMapping';
import { ContainerAddStixCoreObjectsLine_node$data } from '@components/common/containers/__generated__/ContainerAddStixCoreObjectsLine_node.graphql';
import ContainerAddStixCoreObjects from '@components/common/containers/ContainerAddStixCoreObjects';
import Box from '@mui/material/Box';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { CheckCircleOutlined, LayersClearOutlined } from '@mui/icons-material';
import {
  ContainerSuggestedMappingContentClearSuggestedMappingMutation,
} from '@components/common/containers/__generated__/ContainerSuggestedMappingContentClearSuggestedMappingMutation.graphql';
import DialogTitle from '@mui/material/DialogTitle';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { decodeMappingData, encodeMappingData } from '../../../../utils/Graph';
import { ContainerSuggestedMappingContentAskSuggestedMappingMutation } from './__generated__/ContainerSuggestedMappingContentAskSuggestedMappingMutation.graphql';
import Transition from '../../../../components/Transition';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

const OPEN$ = new Subject().pipe(debounce(() => timer(500)));

const addSuggestedMappingRelationsMutation = graphql`
  mutation ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation(
    $id: ID!
    $input: StixRefRelationshipsAddInput!
    $commitMessage: String
    $references: [String]
  ) {
    stixCoreObjectEdit(id: $id) {
      relationsAdd(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        id
      }
    }
  }
`;

const askSuggestedMappingMutation = graphql`
  mutation ContainerSuggestedMappingContentAskSuggestedMappingMutation(
    $id: ID!
    $contentSource: String!
    $contentType: AnalysisContentType!
  ) {
    stixCoreObjectEdit(id: $id) {
      askAnalysis(
        contentSource: $contentSource
        contentType: $contentType
      )
      {
        id
        connector {
          id
        }
      }
    }
  }
`;

const clearSuggestedMappingMutation = graphql`
  mutation ContainerSuggestedMappingContentClearSuggestedMappingMutation(
    $id: ID!
    $contentSource: String!
    $contentType: AnalysisContentType!
  ) {
    stixCoreObjectEdit(id: $id) {
      analysisClear(
        contentSource: $contentSource
        contentType: $contentType
      )
    }
  }
`;

interface ContainerSuggestedMappingContentComponentProps {
  containerData: ContainerContent_container$data;
  queryRef: PreloadedQuery<ContainerStixCoreObjectsSuggestedMappingQuery>
  loadQuery: (variables: ContainerStixCoreObjectsSuggestedMappingQuery$variables, options?: (UseQueryLoaderLoadQueryOptions | undefined)) => void
}

export type MappedEntityType = NonNullable<NonNullable<ContainerStixCoreObjectsSuggestedMappingQuery$data['stixCoreObjectAnalysis']>['mappedEntities']>[number];

const ContainerSuggestedMappingContentComponent: FunctionComponent<
ContainerSuggestedMappingContentComponentProps
> = ({ containerData, queryRef, loadQuery }) => {
  const { t_i18n } = useFormatter();
  const enableReferences = useIsEnforceReference(containerData.entity_type);
  const { innerHeight } = window;
  const { content_mapping } = containerData;
  const listHeight = innerHeight - 420;

  const suggestedMappingData = usePreloadedQuery<ContainerStixCoreObjectsSuggestedMappingQuery>(
    containerStixCoreObjectsSuggestedMappingQuery,
    queryRef,
  );

  const workInProgress = suggestedMappingData.stixCoreObjectAnalysis?.analysisStatus
    ? suggestedMappingData.stixCoreObjectAnalysis?.analysisStatus === 'wait' || suggestedMappingData.stixCoreObjectAnalysis?.analysisStatus === 'progress'
    : false;

  const LOCAL_STORAGE_KEY = `container-${containerData.id}-stixCoreObjectsMapping`;
  const {
    paginationOptions,
  } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      id: containerData.id,
      types: ['Stix-Core-Object'],
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: false,
      openExports: false,
      view: 'mapping',
    },
    true,
  );

  const [open, setOpen] = useState(false);
  const [openClearMapping, setOpenClearMapping] = useState(false);
  const [openValidate, setOpenValidate] = useState(false);
  const [validating, setValidating] = useState(false);
  const [selectedText, setSelectedText] = useState('');
  const [clearing, setClearing] = useState(false);
  useEffect(() => {
    const subscription = OPEN$.subscribe({
      next: () => {
        setOpen(true);
      },
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);
  const [askingSuggestion, setAskingSuggestion] = useState(workInProgress);
  const [removedEntities, setRemovedEntities] = useState<string[]>([]);
  const [inSuggestedMode, setInSuggestedMode] = useState(false);
  const analysisStatus = useRef('');

  const [commitFieldPatch] = useApiMutation<ContainerContentFieldPatchMutation>(contentMutationFieldPatch);
  const [commitRelationsAdd] = useApiMutation<ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation>(addSuggestedMappingRelationsMutation);
  const [commitAnalysisAsk] = useApiMutation<ContainerSuggestedMappingContentAskSuggestedMappingMutation>(askSuggestedMappingMutation);
  const [commitAnalysisClear] = useApiMutation<ContainerSuggestedMappingContentClearSuggestedMappingMutation>(clearSuggestedMappingMutation);

  const mappedEntities = (suggestedMappingData?.stixCoreObjectAnalysis?.mappedEntities ?? []);
  const filterRemovedEntities = (mappedEntity: MappedEntityType) => {
    return !removedEntities.find((r) => r === mappedEntity.matchedEntity?.id);
  };
  const filteredSuggestedMappedEntities = mappedEntities.filter((e) => filterRemovedEntities(e));

  useEffect(() => {
    analysisStatus.current = suggestedMappingData.stixCoreObjectAnalysis?.analysisStatus ?? '';
    if (analysisStatus.current === 'complete') {
      setAskingSuggestion(false);
    }
  }, [suggestedMappingData]);

  useEffect(() => {
    const fetchSuggestedMapping = () => {
      if (askingSuggestion) {
        loadQuery(
          { id: containerData.id, contentSource: 'content_mapping', contentType: 'fields' },
          { fetchPolicy: 'store-and-network' },
        );
      }
    };
    const interval = setInterval(fetchSuggestedMapping, 2000);
    return () => clearInterval(interval);
  }, [loadQuery, containerData, askingSuggestion]);

  const countMappingMatch = (mappedStrings: string[]) => {
    if (!mappedStrings) return {};
    const { description, contentField } = containerData;
    const contentMapping: Record<string, number> = {};
    for (const mappedString of mappedStrings) {
      const escapedMappedString = mappedString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const descriptionRegex = new RegExp(`\\b(${escapedMappedString})\\b`, 'gi');
      const descriptionCount = (
        (description || '').match(descriptionRegex) || []
      ).length;
      const contentRegex = new RegExp(`\\b(${escapedMappedString})\\b`, 'gi');
      const contentCount = ((contentField || '').match(contentRegex) || []).length;
      contentMapping[mappedString] = descriptionCount + contentCount;
    }
    return contentMapping;
  };

  const handleRemoveSuggestedMappingLine = (matchedId: string) => {
    setRemovedEntities([...removedEntities, matchedId]);
  };

  const suggestedMappedStrings = suggestedMappingData.stixCoreObjectAnalysis?.mappedEntities
    ?.filter((e) => !removedEntities.find((r) => r === e.matchedEntity?.id))
    .map((e) => e?.matchedString);
  const suggestedMappingCount = countMappingMatch(suggestedMappedStrings ?? []);

  const contentMappingData = decodeMappingData(content_mapping);
  const mappedStrings = Object.keys(contentMappingData);
  const mappedStringsCount = countMappingMatch(mappedStrings);

  const handleAskNewSuggestedMapping = () => {
    setAskingSuggestion(true);
    analysisStatus.current = '';
    commitAnalysisAsk({
      variables: {
        id: containerData.id,
        contentSource: 'content_mapping',
        contentType: 'fields',
      },
      onCompleted: (response) => {
        MESSAGING$.notifySuccess(
          <span>
            {t_i18n(
              'New suggested mapping has been asked. You can monitor the progress on',
            )}{' '}
            <Link to={`/dashboard/data/ingestion/connectors/${response?.stixCoreObjectEdit?.askAnalysis?.connector?.id}`}>
              {t_i18n('the dedicated page')}
            </Link>
            .
          </span>,
        );
      },
    });
  };

  const addSuggestedMappingEntitiesToContainer = (suggestedMappingEntities: string[]) => {
    commitRelationsAdd({
      variables: {
        id: containerData.id,
        input: {
          relationship_type: 'object',
          toIds: suggestedMappingEntities,
        },
      },
    });
  };

  const addSuggestedMappingToCurrentMapping = () => {
    let newMappingData = decodeMappingData(content_mapping);
    for (let i = 0; i < filteredSuggestedMappedEntities.length; i += 1) {
      const suggestedMapping = filteredSuggestedMappedEntities[i];
      newMappingData = {
        ...newMappingData,
        [suggestedMapping.matchedString]: suggestedMapping.matchedEntity.standard_id,
      };
    }
    commitFieldPatch({
      variables: {
        id: containerData.id,
        input: [{
          key: 'content_mapping',
          value: [encodeMappingData(newMappingData)],
        }],
      },
      onCompleted: () => {
        setInSuggestedMode(false);
        setValidating(false);
        setRemovedEntities([]);
      },
    });
  };

  const clearSuggestedMapping = () => {
    commitAnalysisClear({
      variables: {
        id: containerData.id,
        contentSource: 'content_mapping',
        contentType: 'fields',
      },
    });
  };

  const validateSuggestedMapping = () => {
    const suggestedMappingEntities = filteredSuggestedMappedEntities.map((m) => m.matchedEntity.id);
    addSuggestedMappingEntitiesToContainer(suggestedMappingEntities);
    addSuggestedMappingToCurrentMapping();
    clearSuggestedMapping();
  };

  const handleTextSelection = (text: string) => {
    if (text && text.length > 2) {
      setSelectedText(text.trim());
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      OPEN$.next({ action: 'OpenMapping' });
    }
  };

  const addMapping = (stixCoreObject: ContainerAddStixCoreObjectsLine_node$data) => {
    const newMappingData = {
      ...contentMappingData,
      [selectedText.toLowerCase()]: stixCoreObject.standard_id,
    };
    commitFieldPatch({
      variables: {
        id: containerData.id,
        input: [{
          key: 'content_mapping',
          value: [encodeMappingData(newMappingData)],
        }],
      },
      onCompleted: () => {
        setOpen(false);
        setSelectedText('');
      },
    });
  };

  const clearMapping = () => {
    setClearing(true);
    commitFieldPatch({
      variables: {
        id: containerData.id,
        input: [{
          key: 'content_mapping',
          value: [encodeMappingData({})],
        }],
      },
      onCompleted: () => {
        setClearing(false);
        setOpenClearMapping(false);
      },
    });
  };

  const handleValidate = () => {
    setValidating(true);
    validateSuggestedMapping();
  };

  const hasConnectorsAvailable = suggestedMappingData?.connectorsForAnalysis?.length && suggestedMappingData?.connectorsForAnalysis?.length > 0;
  const suggestDisabled = !hasConnectorsAvailable || askingSuggestion;
  return (
    <div>
      <Grid
        container
        spacing={3}
      >
        <Grid item={true} xs={6} style={{ marginTop: 0, paddingTop: 0 }}>
          <StixCoreObjectMappableContent
            containerData={containerData}
            handleTextSelection={handleTextSelection}
            askAi={false}
            editionMode={false}
            mappedStrings={mappedStrings}
            suggestedMappedStrings={inSuggestedMode ? suggestedMappedStrings : []}
          />
        </Grid>

        <Grid item xs={6} style={{ marginTop: 0, paddingTop: 0 }}>
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={openValidate}
            keepMounted
            TransitionComponent={Transition}
            onClose={() => setOpenValidate(false)}
          >
            <DialogTitle>
              {t_i18n('Are you sure?')}
            </DialogTitle>
            <DialogContent>
              <DialogContentText>
                {t_i18n('You are about to validate this mapping, it will add suggested entities to your container.')}
              </DialogContentText>
            </DialogContent>
            <DialogActions>
              <Button
                onClick={() => setOpenValidate(false)}
                disabled={validating}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={handleValidate}
                disabled={validating}
              >
                {t_i18n('Validate')}
              </Button>
            </DialogActions>
          </Dialog>
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={openClearMapping}
            keepMounted
            TransitionComponent={Transition}
            onClose={() => setOpenClearMapping(false)}
          >
            <DialogContent>
              <DialogContentText>
                {t_i18n('Do you want to delete the mapping of this content?')}
              </DialogContentText>
            </DialogContent>
            <DialogActions>
              <Button
                onClick={() => setOpenClearMapping(false)}
                disabled={clearing}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={() => clearMapping()}
                disabled={clearing}
              >
                {t_i18n('Clear')}
              </Button>
            </DialogActions>
          </Dialog>
          <Paper
            variant="outlined"
            style={{
              height: '100%',
              minHeight: '100%',
              padding: '15px',
              borderRadius: 4,
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Box sx={{}}>
                <FormGroup>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={inSuggestedMode}
                        onChange={() => { setInSuggestedMode(!inSuggestedMode); }}
                        disabled={askingSuggestion || suggestedMappingData?.stixCoreObjectAnalysis?.analysisStatus != 'complete' }
                      />
                    }
                    label={t_i18n('Show suggested mapping')}
                  />
                </FormGroup>
              </Box>

              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                {!hasConnectorsAvailable && (
                  <Tooltip
                    title={t_i18n('An analysis connector needs to be available to ask for a mapping suggestion.')}
                  >
                    <InformationOutline fontSize="small" color="primary" />
                  </Tooltip>
                )}
                {askingSuggestion && (
                  <Tooltip
                    title={t_i18n('An analysis is ongoing, waiting for results.')}
                  >
                    <InformationOutline fontSize="small" color="primary" />
                  </Tooltip>
                )}
                <Tooltip title={t_i18n('Suggest new mapping')}>
                  <Button
                    variant="contained"
                    size="small"
                    onClick={handleAskNewSuggestedMapping}
                    disabled={suggestDisabled}
                  >
                    {t_i18n('Suggest new mapping')}
                  </Button>
                </Tooltip>
                {!inSuggestedMode && (
                  <Tooltip title={t_i18n('Clear mappings')}>
                    <Button
                      variant="contained"
                      onClick={() => setOpenClearMapping(true)}
                      startIcon={<LayersClearOutlined />}
                      size="small"
                    >
                      {t_i18n('Clear mappings')}
                    </Button>
                  </Tooltip>
                )}
                {inSuggestedMode && (
                  <Tooltip title={t_i18n('Validate suggested mapping')}>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={() => setOpenValidate(true)}
                      startIcon={<CheckCircleOutlined />}
                      size="small"
                      disabled={askingSuggestion || filteredSuggestedMappedEntities.length === 0}
                    >
                      {t_i18n('Validate')}
                    </Button>
                  </Tooltip>
                )}
              </Box>
            </Box>
            {!inSuggestedMode && (
              <ContainerStixCoreObjectsMapping
                container={containerData}
                height={listHeight}
                contentMappingData={contentMappingData}
                contentMappingCount={mappedStringsCount}
                enableReferences={enableReferences}
              />
            )}
            {inSuggestedMode && (
              <ContainerStixCoreObjectsSuggestedMapping
                container={containerData}
                suggestedEntities={filteredSuggestedMappedEntities}
                suggestedMappingCount={suggestedMappingCount}
                height={listHeight}
                askingSuggestion={askingSuggestion}
                handleRemoveSuggestedMappingLine={handleRemoveSuggestedMappingLine}
              />
            )}
          </Paper>
        </Grid>
      </Grid>
      <ContainerAddStixCoreObjects
        containerId={containerData.id}
        mapping={true}
        selectedText={selectedText}
        openDrawer={open}
        handleClose={() => {
          setOpen(false);
          setSelectedText('');
        }}
        defaultCreatedBy={containerData.createdBy ?? null}
        defaultMarkingDefinitions={containerData.objectMarking ?? []}
        targetStixCoreObjectTypes={[
          'Stix-Domain-Object',
          'Stix-Cyber-Observable',
        ]}
        confidence={containerData.confidence}
        paginationOptions={paginationOptions}
        onAdd={addMapping}
        enableReferences={enableReferences}
        containerStixCoreObjects={Object.values(contentMappingData).map((c) => ({ node: { id: c } }))}
      />
    </div>
  );
};

interface ContainerSuggestedMappingContentProps {
  containerFragment: ContainerContentQuery$data['container'];
}

const ContainerSuggestedMappingContent = ({ containerFragment }: ContainerSuggestedMappingContentProps) => {
  const containerData = useFragment<ContainerContent_container$key>(containerContentFragment, containerFragment);
  const [queryRef, loadQuery] = useQueryLoader<ContainerStixCoreObjectsSuggestedMappingQuery>(
    containerStixCoreObjectsSuggestedMappingQuery,
  );

  useEffect(() => {
    if (containerData && !queryRef) {
      loadQuery(
        { id: containerData.id, contentSource: 'content_mapping', contentType: 'fields' },
        { fetchPolicy: 'store-and-network' },
      );
    }
  }, [containerData, queryRef]);

  if (!containerData || !queryRef) {
    return null;
  }

  return (
    <ContainerSuggestedMappingContentComponent
      containerData={containerData}
      queryRef={queryRef}
      loadQuery={loadQuery}
    />
  );
};

export default ContainerSuggestedMappingContent;
