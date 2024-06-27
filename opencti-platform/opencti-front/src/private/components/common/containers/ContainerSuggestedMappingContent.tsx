import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader, UseQueryLoaderLoadQueryOptions } from 'react-relay';
import Grid from '@mui/material/Grid';
import StixCoreObjectMappableContent from '@components/common/stix_core_objects/StixCoreObjectMappableContent';
import Paper from '@mui/material/Paper';
import { Link, useNavigate } from 'react-router-dom';
import { containerContentFragment, contentMutationFieldPatch } from '@components/common/containers/ContainerContent';
import ContainerStixCoreObjectsSuggestedMapping, { containerStixCoreObjectsSuggestedMappingQuery } from '@components/common/containers/ContainerStixCoreObjectsSuggestedMapping';
import {
  ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation,
} from '@components/common/containers/__generated__/ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation.graphql';
import { ContainerContentFieldPatchMutation } from '@components/common/containers/__generated__/ContainerContentFieldPatchMutation.graphql';
import {
  ContainerStixCoreObjectsSuggestedMappingQuery,
  ContainerStixCoreObjectsSuggestedMappingQuery$variables,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import { ContainerContent_container$data, ContainerContent_container$key } from '@components/common/containers/__generated__/ContainerContent_container.graphql';
import { ContainerContentQuery$data } from '@components/common/containers/__generated__/ContainerContentQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { decodeMappingData, encodeMappingData } from '../../../../utils/Graph';
import { resolveLink } from '../../../../utils/Entity';
import { ContainerSuggestedMappingContentAskSuggestedMappingMutation } from './__generated__/ContainerSuggestedMappingContentAskSuggestedMappingMutation.graphql';

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

interface ContainerSuggestedMappingContentComponentProps {
  containerData: ContainerContent_container$data;
  queryRef: PreloadedQuery<ContainerStixCoreObjectsSuggestedMappingQuery>
  loadQuery: (variables: ContainerStixCoreObjectsSuggestedMappingQuery$variables, options?: (UseQueryLoaderLoadQueryOptions | undefined)) => void
}

const ContainerSuggestedMappingContentComponent: FunctionComponent<
ContainerSuggestedMappingContentComponentProps
> = ({ containerData, queryRef, loadQuery }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { innerHeight } = window;
  const listHeight = innerHeight - 420;

  const data = usePreloadedQuery<ContainerStixCoreObjectsSuggestedMappingQuery>(
    containerStixCoreObjectsSuggestedMappingQuery,
    queryRef,
  );

  const workInProgress = data.stixCoreObjectAnalysis?.analysisStatus
    ? data.stixCoreObjectAnalysis?.analysisStatus === 'wait' || data.stixCoreObjectAnalysis?.analysisStatus === 'progress'
    : false;

  const [askingSuggestion, setAskingSuggestion] = useState(workInProgress);
  const analysisStatus = useRef('');

  const [commitFieldPatch] = useApiMutation<ContainerContentFieldPatchMutation>(contentMutationFieldPatch);
  const [commitRelationsAdd] = useApiMutation<ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation>(addSuggestedMappingRelationsMutation);
  const [commitAnalysisAsk] = useApiMutation<ContainerSuggestedMappingContentAskSuggestedMappingMutation>(askSuggestedMappingMutation);

  useEffect(() => {
    analysisStatus.current = data.stixCoreObjectAnalysis?.analysisStatus ?? '';
    if (analysisStatus.current === 'complete') {
      setAskingSuggestion(false);
    }
  }, [data]);

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

  const suggestedMappedStrings = data.stixCoreObjectAnalysis?.mappedEntities?.map((e) => e?.matchedString);
  const suggestedMappingCount = countMappingMatch(suggestedMappedStrings ?? []);

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

  const addSuggestedMappingToCurrentMapping = (suggestedMappings: { matchedString: string, matchedEntityId: string }[]) => {
    const { content_mapping } = containerData;
    let newMappingData = decodeMappingData(content_mapping);
    for (let i = 0; i < suggestedMappings.length; i += 1) {
      const suggestedMapping = suggestedMappings[i];
      newMappingData = {
        ...newMappingData,
        [suggestedMapping.matchedString]: suggestedMapping.matchedEntityId,
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
        navigate(
          `${resolveLink(containerData.entity_type)}/${containerData.id}/content/mapping`,
        );
      },
    });
  };

  const validateSuggestedMapping = (suggestedMapping: { matchedString: string, matchedEntityId: string }[]) => {
    const suggestedMappingEntities = suggestedMapping.map((m) => m.matchedEntityId);
    addSuggestedMappingEntitiesToContainer(suggestedMappingEntities);
    addSuggestedMappingToCurrentMapping(suggestedMapping);
  };

  return (
    <Grid
      container
      spacing={3}
    >
      <Grid item={true} xs={6} style={{ marginTop: 0, paddingTop: 0 }}>
        <StixCoreObjectMappableContent
          containerData={containerData}
          askAi={false}
          editionMode={false}
          suggestedMappedStrings={suggestedMappedStrings}
        />
      </Grid>

      <Grid item xs={6} style={{ marginTop: 0, paddingTop: 0 }}>
        <Paper
          variant="outlined"
          style={{
            height: '100%',
            minHeight: '100%',
            padding: '15px',
            borderRadius: 4,
          }}
        >
          <ContainerStixCoreObjectsSuggestedMapping
            container={containerData}
            suggestedMapping={data}
            suggestedMappingCount={suggestedMappingCount}
            height={listHeight}
            handleAskNewSuggestedMapping={handleAskNewSuggestedMapping}
            handleValidateSuggestedMapping={validateSuggestedMapping}
            askingSuggestion={askingSuggestion}
          />
        </Paper>
      </Grid>
    </Grid>
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
