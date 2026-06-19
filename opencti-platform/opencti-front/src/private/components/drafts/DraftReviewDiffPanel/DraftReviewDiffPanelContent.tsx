import React, { FunctionComponent, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import LaunchIcon from '@mui/icons-material/Launch';
import { Link } from 'react-router-dom';
import Loader from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import { containerTypes } from '../../../../utils/hooks/useAttributes';
import { ErrorBoundary } from '../../Error';
import { DraftEntitySelection } from '../DraftReviewEntityList';
import { DraftReviewDiffPanelContentQuery } from './__generated__/DraftReviewDiffPanelContentQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { buildFieldLabelMap, parseUpdatesPatch, RenderChangeValuesFn } from './draftReviewDiffPanelUtils';
import ContainerObjectsTab from './ContainerObjectsTab';
import EntityRelationsTab from './EntityRelationsTab';
import EntityContainerRefsTab from './EntityContainerRefsTab';
import DraftReviewResolvedChanges from './DraftReviewResolvedChanges';
import DraftReviewEntityFields from './DraftReviewEntityFields';

const draftReviewDiffPanelContentQuery = graphql`
  query DraftReviewDiffPanelContentQuery($entityType: String!) {
    subType(id: $entityType) {
      settings {
        attributeLabels {
          name
          label
        }
      }
    }
  }
`;

interface DraftReviewDiffPanelContentComponentProps {
  queryRef: PreloadedQuery<DraftReviewDiffPanelContentQuery>;
  draftId: string;
  entity: DraftEntitySelection;
}

const DraftReviewDiffPanelContentComponent: FunctionComponent<DraftReviewDiffPanelContentComponentProps> = ({
  queryRef,
  draftId,
  entity,
}) => {
  const { t_i18n } = useFormatter();
  const entityId = entity.id;

  const subTypeData = usePreloadedQuery<DraftReviewDiffPanelContentQuery>(
    draftReviewDiffPanelContentQuery,
    queryRef,
  );

  const labelMap = buildFieldLabelMap(subTypeData.subType?.settings?.attributeLabels);

  const renderHeader = () => {
    const link = resolveLink(entity.entity_type);
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3, gap: 1 }}>
        <Typography sx={{ fontFamily: 'Geologica, sans-serif', fontSize: 14, fontWeight: 600, color: 'text.primary', letterSpacing: '0.0075em' }}>
          {entity.representative_main}
        </Typography>
        {link && (
          <IconButton
            component={Link}
            to={`${link}/${entity.id}`}
            target="_blank"
            rel="noopener noreferrer"
            size="small"
            sx={{ width: 26, height: 26, borderRadius: '4px', color: 'primary.main', backgroundColor: 'action.hover' }}
          >
            <LaunchIcon sx={{ fontSize: 18 }} />
          </IconButton>
        )}
      </Box>
    );
  };

  const renderColumnsHeader = () => (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <Typography variant="h3" sx={{ fontWeight: 800 }}>
        {t_i18n('Attributes')}
      </Typography>
      <Box sx={{ display: 'flex', flexDirection: 'row', alignItems: 'center', gap: '7px', width: '100%', mb: '8px' }}>
        <Box sx={{ flex: 1, backgroundColor: 'background.default', borderLeft: '1px solid', borderLeftColor: 'error.main', borderRadius: '4px', py: '6px', display: 'flex', justifyContent: 'center' }}>
          <Typography sx={{ color: 'error.main', fontSize: 10, letterSpacing: '0.0075em' }}>
            {t_i18n('Original Value')}
          </Typography>
        </Box>
        <Box sx={{ flex: 1, backgroundColor: 'background.default', borderLeft: '2px solid', borderLeftColor: 'success.main', borderRadius: '4px', py: '6px', display: 'flex', justifyContent: 'center' }}>
          <Typography sx={{ color: 'success.main', fontSize: 10, letterSpacing: '0.0075em' }}>
            {t_i18n('New value')}
          </Typography>
        </Box>
      </Box>
    </Box>
  );

  const renderChangeValues: RenderChangeValuesFn = (values, isRemoved = false, idLabelMap = {}) => {
    if (!values || values.length === 0) {
      return (
        <Typography sx={{ color: isRemoved ? 'text.secondary' : 'text.primary', fontSize: 14, letterSpacing: '0.0075em' }}>
          -
        </Typography>
      );
    }
    return values.map((s, i) => {
      const displayValue = idLabelMap[s] ?? s;
      return (
        <Box key={`${s}-${i}`} sx={{ mb: i < values.length - 1 ? 1 : 0, color: isRemoved ? 'text.secondary' : 'text.primary' }}>
          <Typography sx={{ fontSize: 14, color: isRemoved ? 'text.secondary' : 'text.primary', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {displayValue}
          </Typography>
        </Box>
      );
    });
  };

  const operation = entity.draft_operation;
  const isContainer = containerTypes.includes(entity.entity_type);

  if (operation === 'create' || operation === 'delete' || operation === 'delete_linked') {
    const mode = operation === 'create' ? 'create' : 'delete';
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        {renderHeader()}
        {renderColumnsHeader()}
        <ErrorBoundary>
          <DraftReviewEntityFields
            draftId={draftId}
            entityId={entityId}
            mode={mode}
            labelMap={labelMap}
            renderChangeValues={renderChangeValues}
          />
        </ErrorBoundary>
        {isContainer && (
          <ErrorBoundary>
            <Typography variant="h3" sx={{ fontWeight: 800 }}>
              {t_i18n('Entities, observables & relations contained into container')}
            </Typography>
            <ContainerObjectsTab draftId={draftId} containerId={entityId} />
          </ErrorBoundary>
        )}
        <ErrorBoundary>
          <Typography variant="h3" sx={{ fontWeight: 800 }}>
            {t_i18n('Relations')}
          </Typography>
          <EntityRelationsTab draftId={draftId} entityId={entityId} />
        </ErrorBoundary>
      </Box>
    );
  }

  const changes = parseUpdatesPatch(entity.draft_updates_patch);

  const renderFieldsTab = () => (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {renderColumnsHeader()}
      {changes.length === 0 ? (
        <Typography variant="body2" sx={{ color: 'text.secondary', mt: 2 }}>
          {t_i18n('No field changes detected for this entity')}
        </Typography>
      ) : (
        <ErrorBoundary>
          <DraftReviewResolvedChanges
            draftId={draftId}
            changes={changes}
            labelMap={labelMap}
            renderChangeValues={renderChangeValues}
          />
        </ErrorBoundary>
      )}
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {renderHeader()}
      {operation !== 'update_linked' && renderFieldsTab()}
      {isContainer && (
        <ErrorBoundary>
          <Typography variant="h3" sx={{ fontWeight: 800 }}>
            {t_i18n('Entities, observables & relations contained into container')}
          </Typography>
          <ContainerObjectsTab draftId={draftId} containerId={entityId} />
        </ErrorBoundary>
      )}
      <ErrorBoundary>
        <Typography variant="h3" sx={{ fontWeight: 800 }}>
          {t_i18n('Relations')}
        </Typography>
        <EntityRelationsTab draftId={draftId} entityId={entityId} />
      </ErrorBoundary>
      <ErrorBoundary>
        <Typography variant="h3" sx={{ fontWeight: 800 }}>
          {t_i18n('Containers')}
        </Typography>
        <EntityContainerRefsTab draftId={draftId} entityId={entityId} />
      </ErrorBoundary>
    </Box>
  );
};

interface DraftReviewDiffPanelContentProps {
  draftId: string;
  entity: DraftEntitySelection;
}

const DraftReviewDiffPanelContent: FunctionComponent<DraftReviewDiffPanelContentProps> = ({ draftId, entity }) => {
  const queryRef = useQueryLoading<DraftReviewDiffPanelContentQuery>(
    draftReviewDiffPanelContentQuery,
    { entityType: entity.entity_type },
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <DraftReviewDiffPanelContentComponent queryRef={queryRef} draftId={draftId} entity={entity} />
      )}
    </Suspense>
  );
};

export default DraftReviewDiffPanelContent;
