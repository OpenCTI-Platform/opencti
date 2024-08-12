import React, { useState } from 'react';
import * as R from 'ramda';
import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import MenuItem from '@mui/material/MenuItem';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import { Select } from '@mui/material';
import makeStyles from '@mui/styles/makeStyles';
import { ConnectionHandler } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { MalwareAnalysisCreationForm } from '../../analyses/malware_analyses/MalwareAnalysisCreation';
import { MalwareCreationForm } from '../../arsenal/malwares/MalwareCreation';
import { AdministrativeAreaCreationForm } from '../../locations/administrative_areas/AdministrativeAreaCreation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { AttackPatternCreationForm } from '../../techniques/attack_patterns/AttackPatternCreation';
import { CampaignCreationForm } from '../../threats/campaigns/CampaignCreation';
import { ChannelCreationForm } from '../../arsenal/channels/ChannelCreation';
import { TaskCreationForm } from '../../cases/tasks/TaskCreation';
import { CityCreationForm } from '../../locations/cities/CityCreation';
import { CountryCreationForm } from '../../locations/countries/CountryCreation';
import { EventCreationForm } from '../../entities/events/EventCreation';
import { GroupingCreationForm } from '../../analyses/groupings/GroupingCreation';
import { IncidentCreationForm } from '../../events/incidents/IncidentCreation';
import { IndicatorCreationForm } from '../../observations/indicators/IndicatorCreation';
import { IndividualCreationForm } from '../../entities/individuals/IndividualCreation';
import { InfrastructureCreationForm } from '../../observations/infrastructures/InfrastructureCreation';
import { IntrusionSetCreationForm } from '../../threats/intrusion_sets/IntrusionSetCreation';
import { ObservedDataCreationForm } from '../../events/observed_data/ObservedDataCreation';
import { OrganizationCreationForm } from '../../entities/organizations/OrganizationCreation';
import { PositionCreationForm } from '../../locations/positions/PositionCreation';
import { RegionCreationForm } from '../../locations/regions/RegionCreation';
import { ReportCreationForm } from '../../analyses/reports/ReportCreation';
import { SectorCreationForm } from '../../entities/sectors/SectorCreation';
import { SystemCreationForm } from '../../entities/systems/SystemCreation';
import { ThreatActorGroupCreationForm } from '../../threats/threat_actors_group/ThreatActorGroupCreation';
import { ToolCreationForm } from '../../arsenal/tools/ToolCreation';
import { VulnerabilityCreationForm } from '../../arsenal/vulnerabilities/VulnerabilityCreation';
import { OpinionCreationFormKnowledgeEditor, OpinionCreationFormKnowledgeParticipant } from '../../analyses/opinions/OpinionCreation';
import { NarrativeCreationForm } from '../../techniques/narratives/NarrativeCreation';
import { DataSourceCreationForm } from '../../techniques/data_sources/DataSourceCreation';
import { DataComponentCreationForm } from '../../techniques/data_components/DataComponentCreation';
import { CourseOfActionCreationForm } from '../../techniques/courses_of_action/CourseOfActionCreation';
import { NoteCreationForm } from '../../analyses/notes/NoteCreation';
import { CaseIncidentCreationForm } from '../../cases/case_incidents/CaseIncidentCreation';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { CaseRfiCreationForm } from '../../cases/case_rfis/CaseRfiCreation';
import { CaseRftCreationForm } from '../../cases/case_rfts/CaseRftCreation';
import { ThreatActorIndividualCreationForm } from '../../threats/threat_actors_individual/ThreatActorIndividualCreation';
import useHelper from '../../../../utils/hooks/useHelper';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';

export const stixDomainObjectCreationAllTypesQuery = graphql`
  query StixDomainObjectCreationAllTypesQuery {
    sdoTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

const UNSUPPORTED_TYPES = ['Language', 'Note', 'Opinion', 'Feedback']; // Language as no ui, note and opinion are not useful
const IDENTITY_ENTITIES = [
  'Sector',
  'Organization',
  'Individual',
  'System',
  'Event',
];
const LOCATION_ENTITIES = [
  'Region',
  'Country',
  'City',
  'Location',
  'Administrative-Area',
];
const CONTAINER_ENTITIES = [
  'Report',
  'Grouping',
  'Case-Incident',
  'Observed-Data',
  'Case-Rfi',
  'Case-Rft',
];
const THREAT_ACTOR_ENTITIES = [
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Threat-Actor',
];

const BULK_ENTITIES = [
  'Administrative-Area',
  'Campaign',
  'Channel',
  'City',
  'Country',
  'Data-Component',
  'Data-Source',
  'Event',
  'Individual',
  'Infrastructure',
  'Intrusion-Set',
  'Malware',
  'Narrative',
  'Organization',
  'Position',
  'Region',
  'Sector',
  'System',
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Tool',
  'Vulnerability',
];

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
});

const sharedUpdater = (
  store,
  userId,
  paginationOptions,
  paginationKey,
  newEdge,
) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    paginationKey,
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const buildEntityTypes = (t, queryData, stixDomainObjectTypes) => {
  const choices = (queryData.sdoTypes?.edges ?? [])
    .map((edge) => ({
      label: t(`entity_${edge.node.label}`),
      value: edge.node.label,
      type: edge.node.label,
    }));
  const entitiesTypes = R.sortWith([R.ascend(R.prop('label'))], choices);
  return entitiesTypes.filter((n) => {
    if (
      !stixDomainObjectTypes
      || stixDomainObjectTypes.length === 0
      || stixDomainObjectTypes.includes('Stix-Domain-Object')
    ) {
      return !UNSUPPORTED_TYPES.includes(n.value);
    }
    if (
      stixDomainObjectTypes.includes('Identity')
      && IDENTITY_ENTITIES.includes(n.value)
    ) {
      return true;
    }
    if (
      stixDomainObjectTypes.includes('Threat-Actor')
      && THREAT_ACTOR_ENTITIES.includes(n.value)
    ) {
      return true;
    }
    if (
      stixDomainObjectTypes.includes('Location')
      && LOCATION_ENTITIES.includes(n.value)
    ) {
      return true;
    }
    if (
      stixDomainObjectTypes.includes('Container')
      && CONTAINER_ENTITIES.includes(n.value)
    ) {
      return true;
    }
    return !!stixDomainObjectTypes.includes(n.value);
  });
};

const StixDomainPanel = ({
  queryRef,
  stixDomainObjectTypes,
  onClose,
  creationUpdater,
  confidence,
  inputValue,
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const { isFeatureEnable } = useHelper();
  const [bulkOpen, setBulkOpen] = useState(false);
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(
    stixDomainObjectCreationAllTypesQuery,
    queryRef,
  );
  const availableEntityTypes = buildEntityTypes(
    t_i18n,
    queryData,
    stixDomainObjectTypes,
  );
  const [type, setType] = useState(availableEntityTypes.at(0).value);
  const baseCreatedBy = defaultCreatedBy
    ? { value: defaultCreatedBy.id, label: defaultCreatedBy.name }
    : undefined;
  const baseMarkingDefinitions = (defaultMarkingDefinitions ?? []).map((n) => ({
    label: n.definition,
    value: n.id,
    color: n.x_opencti_color,
    entity: n,
  }));

  const renderEntityCreationInterface = () => {
    if (type === 'Administrative-Area') {
      return (
        <AdministrativeAreaCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Attack-Pattern') {
      return (
        <AttackPatternCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Campaign') {
      return (
        <CampaignCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Case-Incident') {
      // Default to Incident case type
      return (
        <CaseIncidentCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onClose={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Case-Rfi') {
      return (
        <CaseRfiCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onClose={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Case-Rft') {
      return (
        <CaseRftCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onClose={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Channel') {
      return (
        <ChannelCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'City') {
      return (
        <CityCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Country') {
      return (
        <CountryCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Course-Of-Action') {
      // Course-Of-Action
      return (
        <CourseOfActionCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Data-Component') {
      // Data-Component
      return (
        <DataComponentCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Data-Source') {
      // Data-Source
      return (
        <DataSourceCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Event') {
      // Event
      return (
        <EventCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Grouping') {
      // Grouping
      return (
        <GroupingCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onClose={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Incident') {
      // Incident
      return (
        <IncidentCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Indicator') {
      // Indicator
      return (
        <IndicatorCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Individual') {
      // Individual
      return (
        <IndividualCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Infrastructure') {
      // Infrastructure
      return (
        <InfrastructureCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Intrusion-Set') {
      // IntrusionSet
      return (
        <IntrusionSetCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Malware') {
      // Malware
      return (
        <MalwareCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Narrative') {
      // Narrative
      return (
        <NarrativeCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Note') {
      // Note
      return (
        <NoteCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Observed-Data') {
      // Observed data
      return (
        <ObservedDataCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Opinion') {
      // Opinion
      const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
      return userIsKnowledgeEditor ? (
        <OpinionCreationFormKnowledgeEditor
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      ) : (
        <OpinionCreationFormKnowledgeParticipant
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Organization') {
      // Organization
      return (
        <OrganizationCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Position') {
      // Position
      return (
        <PositionCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Region') {
      // Region
      return (
        <RegionCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Report') {
      // Report
      return (
        <ReportCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onClose={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Sector') {
      // Sector
      return (
        <SectorCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'System') {
      // System
      return (
        <SystemCreationForm
          inputValue={inputValue}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Threat-Actor-Group') {
      return (
        <ThreatActorGroupCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Threat-Actor-Individual') {
      return (
        <ThreatActorIndividualCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Tool') {
      // Tool
      return (
        <ToolCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Vulnerability') {
      // Vulnerability
      return (
        <VulnerabilityCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
          bulkModalOpen={bulkOpen}
          onBulkModalClose={() => setBulkOpen(false)}
          onCompleted={onClose}
        />
      );
    }
    if (type === 'Malware-Analysis') {
      // Malware-Analysis
      return (
        <MalwareAnalysisCreationForm
          inputValue={inputValue}
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onClose={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Task') {
      // Task
      return (
        <TaskCreationForm
          inputValue={inputValue}
          defaultMarkings={baseMarkingDefinitions}
          onClose={onClose}
          updater={creationUpdater}
        />
      );
    }
    return <div style={{ marginTop: 10 }}>{t_i18n('Unsupported')}</div>;
  };

  return (
    <Dialog
      PaperProps={{ elevation: 1 }}
      open={true}
      onClose={onClose}
      fullWidth={true}
    >
      <DialogTitle style={{ display: 'flex' }}>
        {t_i18n('Create an entity')}
        {isFeatureEnable('BULK_ENTITIES') && (
          <BulkTextModalButton
            onClick={() => setBulkOpen(true)}
            sx={{ marginRight: 0 }}
            disabled={!BULK_ENTITIES.includes(type)}
          />
        )}
      </DialogTitle>
      <DialogContent>
        <Select
          value={type}
          onChange={(event) => setType(event.target.value)}
          fullWidth={true}
          size="small"
        >
          {availableEntityTypes.map((availableType) => (
            <MenuItem key={availableType.value} value={availableType.value}>
              {availableType.label}
            </MenuItem>
          ))}
        </Select>
        {renderEntityCreationInterface()}
      </DialogContent>
    </Dialog>
  );
};

const StixDomainObjectCreation = ({
  creationCallback,
  inputValue,
  confidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  stixDomainObjectTypes,
  display,
  open,
  speeddial,
  handleClose,
  paginationKey,
  paginationOptions,
}) => {
  const classes = useStyles();
  const [status, setStatus] = useState({ open: false, type: null });
  const [queryRef, loadQuery] = useQueryLoader(
    stixDomainObjectCreationAllTypesQuery,
  );
  const isOpen = speeddial ? open : status.open;
  // In speed dial mode the open/close is handled by a parent
  // So we need to load only once directly
  if (speeddial && open && !queryRef) {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }
  const stateHandleOpen = () => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
    setStatus({ open: true, type: null });
  };
  const stateHandleClose = () => setStatus({ open: false, type: null });

  const creationUpdater = (store, rootField, element) => {
    const payload = store.getRootField(rootField);
    if (creationCallback) {
      creationCallback(element);
    } else {
      const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
      const container = store.getRoot();
      sharedUpdater(
        store,
        container.getDataID(),
        paginationOptions,
        paginationKey || 'Pagination_stixDomainObjects',
        newEdge,
      );
    }
  };

  return (
    <div style={{ display: display ? 'block' : 'none' }}>
      {!speeddial && (
        <Fab
          onClick={stateHandleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
      )}
      {isOpen && queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixDomainPanel
            queryRef={queryRef}
            inputValue={inputValue}
            confidence={confidence}
            defaultCreatedBy={defaultCreatedBy}
            defaultMarkingDefinitions={defaultMarkingDefinitions}
            stixDomainObjectTypes={stixDomainObjectTypes}
            creationUpdater={creationUpdater}
            onClose={speeddial ? handleClose : stateHandleClose}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default StixDomainObjectCreation;
