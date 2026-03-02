import Dialog from '@common/dialog/Dialog';
import Alert from '@mui/lab/Alert';
import { Select, Stack } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import * as R from 'ramda';
import React, { useState } from 'react';
import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import FormControl from '@mui/material/FormControl';
import MenuItem from '@mui/material/MenuItem';
import { Select } from '@mui/material';
import { ConnectionHandler } from 'relay-runtime';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { GroupingCreationForm } from '../../analyses/groupings/GroupingCreation';
import { MalwareAnalysisCreationForm } from '../../analyses/malware_analyses/MalwareAnalysisCreation';
import { NoteCreationForm } from '../../analyses/notes/NoteCreation';
import { OpinionCreationFormKnowledgeEditor, OpinionCreationFormKnowledgeParticipant } from '../../analyses/opinions/OpinionCreation';
import { ReportCreationForm } from '../../analyses/reports/ReportCreation';
import { SecurityCoverageCreationForm } from '../../analyses/security_coverages/SecurityCoverageCreation';
import { ChannelCreationForm } from '../../arsenal/channels/ChannelCreation';
import { MalwareCreationForm } from '../../arsenal/malwares/MalwareCreation';
import { ToolCreationForm } from '../../arsenal/tools/ToolCreation';
import { VulnerabilityCreationForm } from '../../arsenal/vulnerabilities/VulnerabilityCreation';
import { CaseIncidentCreationForm } from '../../cases/case_incidents/CaseIncidentCreation';
import { CaseRfiCreationForm } from '../../cases/case_rfis/CaseRfiCreation';
import { CaseRftCreationForm } from '../../cases/case_rfts/CaseRftCreation';
import { TaskCreationForm } from '../../cases/tasks/TaskCreation';
import { EventCreationForm } from '../../entities/events/EventCreation';
import { IndividualCreationForm } from '../../entities/individuals/IndividualCreation';
import { OrganizationCreationForm } from '../../entities/organizations/OrganizationCreation';
import { SectorCreationForm } from '../../entities/sectors/SectorCreation';
import { SystemCreationForm } from '../../entities/systems/SystemCreation';
import { IncidentCreationForm } from '../../events/incidents/IncidentCreation';
import { ObservedDataCreationForm } from '../../events/observed_data/ObservedDataCreation';
import { AdministrativeAreaCreationForm } from '../../locations/administrative_areas/AdministrativeAreaCreation';
import { CityCreationForm } from '../../locations/cities/CityCreation';
import { CountryCreationForm } from '../../locations/countries/CountryCreation';
import { PositionCreationForm } from '../../locations/positions/PositionCreation';
import { RegionCreationForm } from '../../locations/regions/RegionCreation';
import { IndicatorCreationForm } from '../../observations/indicators/IndicatorCreation';
import { InfrastructureCreationForm } from '../../observations/infrastructures/InfrastructureCreation';
import { AttackPatternCreationForm } from '../../techniques/attack_patterns/AttackPatternCreation';
import { CourseOfActionCreationForm } from '../../techniques/courses_of_action/CourseOfActionCreation';
import { DataComponentCreationForm } from '../../techniques/data_components/DataComponentCreation';
import { DataSourceCreationForm } from '../../techniques/data_sources/DataSourceCreation';
import { NarrativeCreationForm } from '../../techniques/narratives/NarrativeCreation';
import { CampaignCreationForm } from '../../threats/campaigns/CampaignCreation';
import { IntrusionSetCreationForm } from '../../threats/intrusion_sets/IntrusionSetCreation';
import { ThreatActorGroupCreationForm } from '../../threats/threat_actors_group/ThreatActorGroupCreation';
import { ThreatActorIndividualCreationForm } from '../../threats/threat_actors_individual/ThreatActorIndividualCreation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import BulkTextModalButton from '../../../../components/fields/BulkTextField/BulkTextModalButton';
import InputLabel from '@mui/material/InputLabel';

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

const sharedUpdater = (
  store,
  userId,
  paginationOptions,
  paginationKey,
  newEdge,
) => {
  const userProxy = store.get(userId);
  const params = { ...paginationOptions };
  delete params.count;
  const conn = ConnectionHandler.getConnection(
    userProxy,
    paginationKey,
    params,
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
  onCompleted,
  creationUpdater,
  confidence,
  inputValue,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  isFromBulkRelation,
}) => {
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
  const selectedType = availableEntityTypes.find((item) => item.value === stixDomainObjectTypes) ?? availableEntityTypes.at(0);
  const [type, setType] = useState(selectedType.value);
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
          onCompleted={onCompleted ?? onClose}
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
    if (type === 'Security-Coverage') {
      // Security-Coverage
      return (
        <SecurityCoverageCreationForm
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

  const renderUnavailableBulkMessage = () => {
    if (isFromBulkRelation && !BULK_ENTITIES.includes(type)) {
      return (
        <Alert
          severity="info"
          variant="outlined"
          style={{ marginBottom: 10 }}
        >
          {t_i18n('This entity has several key fields, which is incompatible with bulk creation')}
        </Alert>
      );
    }
    return null;
  };

  return (
    <Dialog
      open={true}
      onClose={onClose}
      title={(
        <Stack direction="row" justifyContent="space-between">
          <span>{t_i18n('Create an entity')}</span>
          {!isFromBulkRelation && (
            <BulkTextModalButton
              onClick={() => setBulkOpen(true)}
              sx={{ marginRight: 0 }}
              disabled={!BULK_ENTITIES.includes(type)}
            />
          )}
        </Stack>
      )}
    >

      <DialogContent>
        {renderUnavailableBulkMessage()}
        <FormControl
          style={{ width: '100%' }}
        >
          <InputLabel id="form_create_entity_entity_type">
            {t_i18n('Entity type')}
          </InputLabel>
          <Select
            value={type}
            onChange={(event) => setType(event.target.value)}
            fullWidth={true}
            size="small"
            labelId="form_create_entity_entity_type"
          >
            {availableEntityTypes.map((availableType) => (
              <MenuItem key={availableType.value} value={availableType.value}>
                {availableType.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <div style={{ marginTop: '20px' }}>
          {renderEntityCreationInterface()}
        </div>
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
  controlledDialStyles = {},
  controlledDialSize = undefined,
  handleClose,
  paginationKey,
  paginationOptions,
  onCompleted,
  isFromBulkRelation,
}) => {
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
      if (onCompleted) onCompleted();
    }
  };

  return (
    <>
      {!speeddial && (
        <CreateEntityControlledDial
          entityType={stixDomainObjectTypes?.length === 1 ? stixDomainObjectTypes[0] : 'Stix-Domain-Object'}
          onOpen={stateHandleOpen}
          onClose={() => {}}
          style={controlledDialStyles}
          size={controlledDialSize}
        />
      )}
      <div style={{ display: display ? 'block' : 'none' }}>
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
              onCompleted={onCompleted}
              onClose={speeddial ? handleClose : stateHandleClose}
              isFromBulkRelation={isFromBulkRelation}
            />
          </React.Suspense>
        )}
      </div>
    </>
  );
};

export default StixDomainObjectCreation;
