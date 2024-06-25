import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
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
import { ContainerStixCoreObjectsSuggestedMappingQuery$data } from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql';
import { ContainerContent_container$key } from '@components/common/containers/__generated__/ContainerContent_container.graphql';
import { ContainerContentQuery$data } from '@components/common/containers/__generated__/ContainerContentQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$, QueryRenderer } from '../../../../relay/environment';
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

/* const clearSuggestedMappingMutation = graphql`
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
`; */

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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
}));
interface ContainerSuggestedMappingContentProps {
  containerFragment: ContainerContentQuery$data['container'];
}

const ContainerSuggestedMappingContent: FunctionComponent<
ContainerSuggestedMappingContentProps
> = ({ containerFragment }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { innerHeight } = window;
  const listHeight = innerHeight - 420;

  const [askingSuggestion, setAskingSuggestion] = useState(false);

  const containerData = useFragment<ContainerContent_container$key>(containerContentFragment, containerFragment);

  const [commitFieldPatch] = useApiMutation<ContainerContentFieldPatchMutation>(contentMutationFieldPatch);
  const [commitRelationsAdd] = useApiMutation<ContainerSuggestedMappingContentAddSuggestedMappingRelationsMutation>(addSuggestedMappingRelationsMutation);
  // const [commitAnalysisClear] = useApiMutation<ContainerSuggestedMappingContentClearSuggestedMappingMutation>(clearSuggestedMappingMutation);
  const [commitAnalysisAsk] = useApiMutation<ContainerSuggestedMappingContentAskSuggestedMappingMutation>(askSuggestedMappingMutation);

  if (!containerData) {
    return null;
  }

  const handleAskNewSuggestedMapping = () => {
    setAskingSuggestion(true);
    commitAnalysisAsk({
      variables: {
        id: containerData.id,
        contentSource: 'content_mapping',
        contentType: 'fields',
      },
      onCompleted: (response) => {
        setAskingSuggestion(false);
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

  /*  const clearSuggestedMapping = () => {
      commitAnalysisClear({
        mutation: clearSuggestedMappingMutation,
        variables: {
          id: containerData.id,
          contentSource: 'content_mapping',
          contentType: 'fields',
        },
      });
    }; */

  const validateSuggestedMapping = (suggestedMapping: { matchedString: string, matchedEntityId: string }[]) => {
    const suggestedMappingEntities = suggestedMapping.map((m) => m.matchedEntityId);
    addSuggestedMappingEntitiesToContainer(suggestedMappingEntities);
    addSuggestedMappingToCurrentMapping(suggestedMapping);
    // clearSuggestedMapping();
  };

  const { description, contentField } = containerData;

  const countMappingMatch = (mappedStrings: string[]) => {
    if (!mappedStrings) return {};
    const contentMapping: Record<string, number> = {};
    for (const mappedString of mappedStrings) {
      const escapedMappedString = mappedString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const descriptionRegex = new RegExp(escapedMappedString, 'ig');
      const descriptionCount = (
        (description || '').match(descriptionRegex) || []
      ).length;
      const contentRegex = new RegExp(escapedMappedString, 'ig');
      const contentCount = ((contentField || '').match(contentRegex) || []).length;
      contentMapping[mappedString] = descriptionCount + contentCount;
    }
    return contentMapping;
  };

  return (
    <QueryRenderer
      query={containerStixCoreObjectsSuggestedMappingQuery}
      variables={{ id: containerData.id, contentSource: 'content_mapping', contentType: 'fields' }}
      render={({ props } : { props: ContainerStixCoreObjectsSuggestedMappingQuery$data }) => {
        let isLoading = false;
        if (!props) {
          isLoading = true;
        }
        const suggestedMappedStrings = props?.stixCoreObjectAnalysis?.mappedEntities?.map((e) => e?.matchedString);
        const suggestedMappingCount = countMappingMatch(suggestedMappedStrings ?? []);
        return (
          <Grid
            container
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={6} style={{ marginTop: 0 }}>
              <StixCoreObjectMappableContent
                containerData={containerData}
                askAi={false}
                editionMode={false}
                suggestedMappedStrings={suggestedMappedStrings}
              />
            </Grid>
            <Grid item xs={6} style={{ marginTop: -10 }}>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <ContainerStixCoreObjectsSuggestedMapping
                  container={containerData}
                  suggestedMapping={props}
                  suggestedMappingCount={suggestedMappingCount}
                  height={listHeight}
                  handleAskNewSuggestedMapping={handleAskNewSuggestedMapping}
                  handleValidateSuggestedMapping={validateSuggestedMapping}
                  isLoading={isLoading}
                  askingSuggestion={askingSuggestion}
                />
              </Paper>
            </Grid>
          </Grid>
        );
      }}
    />
  );
};

export default ContainerSuggestedMappingContent;
