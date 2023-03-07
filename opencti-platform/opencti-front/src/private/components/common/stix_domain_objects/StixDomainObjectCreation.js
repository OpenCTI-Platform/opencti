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
import { MalwareCreationForm } from '../../arsenal/malwares/MalwareCreation';
import { AdministrativeAreaCreationForm } from '../../locations/administrative_areas/AdministrativeAreaCreation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { AttackPatternCreationForm } from '../../techniques/attack_patterns/AttackPatternCreation';
import { CampaignCreationForm } from '../../threats/campaigns/CampaignCreation';
import { CaseCreationForm } from '../../cases/incidents/IncidentCreation';
import { ChannelCreationForm } from '../../arsenal/channels/ChannelCreation';
import { CityCreationForm } from '../../locations/cities/CityCreation';
import { CountryCreationForm } from '../../locations/countries/CountryCreation';
import { EventCreationForm } from '../../entities/events/EventCreation';
import { GroupingCreationForm } from '../../analysis/groupings/GroupingCreation';
import { IncidentCreationForm } from '../../events/incidents/IncidentCreation';
import { IndicatorCreationForm } from '../../observations/indicators/IndicatorCreation';
import { IndividualCreationForm } from '../../entities/individuals/IndividualCreation';
import { InfrastructureCreationForm } from '../../observations/infrastructures/InfrastructureCreation';
import { IntrusionSetCreationForm } from '../../threats/intrusion_sets/IntrusionSetCreation';
import { ObservedDataCreationForm } from '../../events/observed_data/ObservedDataCreation';
import { OrganizationCreationForm } from '../../entities/organizations/OrganizationCreation';
import { PositionCreationForm } from '../../locations/positions/PositionCreation';
import { RegionCreationForm } from '../../locations/regions/RegionCreation';
import { ReportCreationForm } from '../../analysis/reports/ReportCreation';
import { SectorCreationForm } from '../../entities/sectors/SectorCreation';
import { SystemCreationForm } from '../../entities/systems/SystemCreation';
import { ThreatActorCreationForm } from '../../threats/threat_actors/ThreatActorCreation';
import { ToolCreationForm } from '../../arsenal/tools/ToolCreation';
import { VulnerabilityCreationForm } from '../../arsenal/vulnerabilities/VulnerabilityCreation';
import { OpinionCreationForm } from '../../analysis/opinions/OpinionCreation';
import { NarrativeCreationForm } from '../../techniques/narratives/NarrativeCreation';
import { DataSourceCreationForm } from '../../techniques/data_sources/DataSourceCreation';
import { DataComponentCreationForm } from '../../techniques/data_components/DataComponentCreation';
import { CourseOfActionCreationForm } from '../../techniques/courses_of_action/CourseOfActionCreation';
import { NoteCreationForm } from '../../analysis/notes/NoteCreation';

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

const UNSUPPORTED_TYPES = ['Language', 'Note', 'Opinion']; // Language as no ui, note and opinion are not useful
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

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

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
  const choices = (queryData.sdoTypes?.edges ?? []).map((edge) => ({
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
      stixDomainObjectTypes.includes('Location')
      && LOCATION_ENTITIES.includes(n.value)
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
  defaultCreatedBy,
  defaultMarkingDefinitions,
}) => {
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(
    stixDomainObjectCreationAllTypesQuery,
    queryRef,
  );
  const availableEntityTypes = buildEntityTypes(
    t,
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
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Attack-Pattern') {
      return (
        <AttackPatternCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Campaign') {
      return (
        <CampaignCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Case') {
      // Default to Incident case type
      return (
        <CaseCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Channel') {
      return (
        <ChannelCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'City') {
      return (
        <CityCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Country') {
      return (
        <CountryCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Course-Of-Action') {
      // Course-Of-Action
      return (
        <CourseOfActionCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Data-Component') {
      // Data-Component
      return (
        <DataComponentCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Data-Source') {
      // Data-Source
      return (
        <DataSourceCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Event') {
      // Event
      return (
        <EventCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Grouping') {
      // Grouping
      return (
        <GroupingCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Incident') {
      // Incident
      return (
        <IncidentCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Indicator') {
      // Indicator
      return (
        <IndicatorCreationForm
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
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Infrastructure') {
      // Infrastructure
      return (
        <InfrastructureCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Intrusion-Set') {
      // IntrusionSet
      return (
        <IntrusionSetCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Malware') {
      // Malware
      return (
        <MalwareCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Narrative') {
      // Narrative
      return (
        <NarrativeCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Note') {
      // Note
      return (
        <NoteCreationForm
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
      return (
        <OpinionCreationForm
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
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Position') {
      // Position
      return (
        <PositionCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Region') {
      // Region
      return (
        <RegionCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Report') {
      // Report
      return (
        <ReportCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Sector') {
      // Sector
      return (
        <SectorCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'System') {
      // System
      return (
        <SystemCreationForm
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Threat-Actor') {
      // Threat-Actor
      return (
        <ThreatActorCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Tool') {
      // Tool
      return (
        <ToolCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    if (type === 'Vulnerability') {
      // Vulnerability
      return (
        <VulnerabilityCreationForm
          defaultConfidence={confidence}
          defaultCreatedBy={baseCreatedBy}
          defaultMarkingDefinitions={baseMarkingDefinitions}
          onReset={onClose}
          updater={creationUpdater}
        />
      );
    }
    return <div>{t('Unsupported')}</div>;
  };

  return (
    <Dialog
      PaperProps={{ elevation: 1 }}
      open={true}
      onClose={onClose}
      fullWidth={true}
    >
      <DialogTitle>{t('Create an entity')}</DialogTitle>
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
  const creationUpdater = (store, rootField) => {
    const payload = store.getRootField(rootField);
    if (creationCallback) {
      creationCallback(payload);
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
    if (speeddial) {
      handleClose();
    } else {
      stateHandleClose();
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
