import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader, UseQueryLoaderLoadQueryOptions } from 'react-relay';
import Grid from '@mui/material/Grid';
import StixCoreObjectMappableContent from '@components/common/stix_core_objects/StixCoreObjectMappableContent';
import Paper from '@mui/material/Paper';
import { Link } from 'react-router-dom';
import ContainerStixCoreObjectsSuggestedMapping, { containerStixCoreObjectsSuggestedMappingQuery } from '@components/common/containers/ContainerStixCoreObjectsSuggestedMapping';
import {
  ContainerStixCoreObjectsSuggestedMappingQuery,
  ContainerStixCoreObjectsSuggestedMappingQuery$data,
  ContainerStixCoreObjectsSuggestedMappingQuery$variables,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import ContainerStixCoreObjectsMapping from '@components/common/containers/ContainerStixCoreObjectsMapping';
import { ContainerAddStixCoreObjectsLine_node$data } from '@components/common/containers/__generated__/ContainerAddStixCoreObjectsLine_node.graphql';
import ContainerAddStixCoreObjects from '@components/common/containers/ContainerAddStixCoreObjects';
import {
  ContainerMappingContent_container$data,
  ContainerMappingContent_container$key,
} from '@components/common/containers/__generated__/ContainerMappingContent_container.graphql';
import { ContainerMappingContentQuery$data } from '@components/common/containers/__generated__/ContainerMappingContentQuery.graphql';
import { ContainerMappingContentFieldPatchMutation } from '@components/common/containers/__generated__/ContainerMappingContentFieldPatchMutation.graphql';
import {
  ContainerMappingContentAddSuggestedMappingRelationsMutation,
} from '@components/common/containers/__generated__/ContainerMappingContentAddSuggestedMappingRelationsMutation.graphql';
import { ContainerMappingContentAskSuggestedMappingMutation } from '@components/common/containers/__generated__/ContainerMappingContentAskSuggestedMappingMutation.graphql';
import { ContainerMappingContentClearSuggestedMappingMutation } from '@components/common/containers/__generated__/ContainerMappingContentClearSuggestedMappingMutation.graphql';
import {
  ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$data,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity.graphql';
import ContainerStixCoreObjectsMappingHeader from '@components/common/containers/ContainerStixCoreObjectsMappingHeader';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { decodeMappingData, encodeMappingData } from '../../../../utils/Graph';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

const OPEN$ = new Subject().pipe(debounce(() => timer(500)));

export const contentMutationFieldPatch = graphql`
  mutation ContainerMappingContentFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ContainerMappingContent_container
      }
    }
  }
`;

export const containerContentQuery = graphql`
  query ContainerMappingContentQuery($id: String!) {
    container(id: $id) {
      ...ContainerMappingContent_container
    }
  }
`;

export const containerContentFragment = graphql`
  fragment ContainerMappingContent_container on Container {
    id
    standard_id
    entity_type
    confidence
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    ... on Report {
      description
      contentField: content
      content_mapping
      editContext {
        name
        focusOn
      }
    }
    ... on Case {
      description
      contentField: content
      content_mapping
      editContext {
        name
        focusOn
      }
    }
    ... on Grouping {
      description
      contentField: content
      content_mapping
      editContext {
        name
        focusOn
      }
    }
  }
`;

const addSuggestedMappingRelationsMutation = graphql`
  mutation ContainerMappingContentAddSuggestedMappingRelationsMutation(
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
  mutation ContainerMappingContentAskSuggestedMappingMutation(
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
  mutation ContainerMappingContentClearSuggestedMappingMutation(
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

interface ContainerMappingContentComponentProps {
  containerData: ContainerMappingContent_container$data;
  queryRef: PreloadedQuery<ContainerStixCoreObjectsSuggestedMappingQuery>
  loadQuery: (variables: ContainerStixCoreObjectsSuggestedMappingQuery$variables, options?: (UseQueryLoaderLoadQueryOptions | undefined)) => void
}

export type MappedEntityType = NonNullable<NonNullable<ContainerStixCoreObjectsSuggestedMappingQuery$data['stixCoreObjectAnalysis']>['mappedEntities']>[number];

const ContainerMappingContentComponent: FunctionComponent<
ContainerMappingContentComponentProps
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

  const LOCAL_STORAGE_KEY = `container-${containerData.id}-mapping`;
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
  const [openValidate, setOpenValidate] = useState(false);
  const [validating, setValidating] = useState(false);
  const [selectedText, setSelectedText] = useState('');
  const [openClearMapping, setOpenClearMapping] = useState(false);
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

  const [commitFieldPatch] = useApiMutation<ContainerMappingContentFieldPatchMutation>(contentMutationFieldPatch);
  const [commitRelationsAdd] = useApiMutation<ContainerMappingContentAddSuggestedMappingRelationsMutation>(addSuggestedMappingRelationsMutation);
  const [commitAnalysisAsk] = useApiMutation<ContainerMappingContentAskSuggestedMappingMutation>(askSuggestedMappingMutation);
  const [commitAnalysisClear] = useApiMutation<ContainerMappingContentClearSuggestedMappingMutation>(clearSuggestedMappingMutation);

  const mappedEntities = (suggestedMappingData.stixCoreObjectAnalysis?.mappedEntities ?? []);
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

  const handleRemoveSuggestedMappingLine = (removedEntity: NonNullable<ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$data['matchedEntity']>) => {
    setRemovedEntities([...removedEntities, removedEntity.id]);
  };

  const contentMappingData = decodeMappingData(content_mapping);
  const mappedStrings = Object.keys(contentMappingData);
  const mappedStringsCount = countMappingMatch(mappedStrings);

  const suggestedMappedStrings = suggestedMappingData.stixCoreObjectAnalysis?.mappedEntities
    ?.filter((e) => !removedEntities.find((r) => r === e.matchedEntity?.id))
    .map((e) => e?.matchedString);
  const suggestedMappingCount = countMappingMatch(suggestedMappedStrings ?? []);
  const filteredSuggestedMappedStrings = suggestedMappedStrings?.filter((s) => !mappedStrings.includes(s));

  const handleAskNewSuggestedMapping = () => {
    setValidating(false);
    setAskingSuggestion(true);
    setInSuggestedMode(false);
    setRemovedEntities([]);
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
        setOpenValidate(false);
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
        setInSuggestedMode(false);
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

  return (
    <>
      <Grid
        container
        spacing={2}
      >
        <Grid item xs={6}>
          <StixCoreObjectMappableContent
            containerData={containerData}
            handleTextSelection={handleTextSelection}
            askAi={false}
            editionMode={false}
            mappedStrings={mappedStrings}
            suggestedMappedStrings={inSuggestedMode ? filteredSuggestedMappedStrings : []}
          />
        </Grid>

        <Grid item xs={6}>
          <Paper
            variant="outlined"
            style={{
              padding: '15px',
              borderRadius: 4,
            }}
          >
            <ContainerStixCoreObjectsMappingHeader
              suggestedMappingData={suggestedMappingData}
              validateDisabled={askingSuggestion || filteredSuggestedMappedEntities.length === 0}
              validating={validating}
              openValidate={openValidate}
              setOpenValidate={setOpenValidate}
              handleValidateMapping={handleValidate}
              openClearMapping={openClearMapping}
              setOpenClearMapping={setOpenClearMapping}
              clearing={clearing}
              handleClearMapping={clearMapping}
              inSuggestedMode={inSuggestedMode}
              setInSuggestedMode={setInSuggestedMode}
              askingSuggestion={askingSuggestion}
              handleAskNewSuggestion={handleAskNewSuggestedMapping}
            />
            <div style={{ margin: 0, padding: '15px 0 0 0' }}>
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
            </div>
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
    </>
  );
};

interface ContainerMappingContentProps {
  containerFragment: ContainerMappingContentQuery$data['container'];
}

const ContainerMappingContent = ({ containerFragment }: ContainerMappingContentProps) => {
  const containerData = useFragment<ContainerMappingContent_container$key>(containerContentFragment, containerFragment);
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
    <ContainerMappingContentComponent
      containerData={containerData}
      queryRef={queryRef}
      loadQuery={loadQuery}
    />
  );
};

export default ContainerMappingContent;
