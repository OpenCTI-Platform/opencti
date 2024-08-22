import * as R from 'ramda';
import SpriteText from 'three-spritetext';
import { fromB64, toB64, truncate } from './String';
import KillChainPhase from '../static/images/entities/kill-chain-phase.svg';
import MarkingDefinition from '../static/images/entities/marking-definition.svg';
import Label from '../static/images/entities/label.svg';
import ExternalReference from '../static/images/entities/external-reference.svg';
import AttackPattern from '../static/images/entities/attack-pattern.svg';
import Campaign from '../static/images/entities/campaign.svg';
import Note from '../static/images/entities/note.svg';
import ObservedData from '../static/images/entities/observed-data.svg';
import Opinion from '../static/images/entities/opinion.svg';
import Report from '../static/images/entities/report.svg';
import Grouping from '../static/images/entities/grouping.svg';
import CourseOfAction from '../static/images/entities/course-of-action.svg';
import Individual from '../static/images/entities/individual.svg';
import Organization from '../static/images/entities/organization.svg';
import Sector from '../static/images/entities/sector.svg';
import System from '../static/images/entities/system.svg';
import Indicator from '../static/images/entities/indicator.svg';
import Infrastructure from '../static/images/entities/infrastructure.svg';
import IntrusionSet from '../static/images/entities/intrusion-set.svg';
import City from '../static/images/entities/city.svg';
import AdministrativeArea from '../static/images/entities/administrative-area.svg';
import Country from '../static/images/entities/country.svg';
import Region from '../static/images/entities/region.svg';
import Position from '../static/images/entities/position.svg';
import Malware from '../static/images/entities/malware.svg';
import ThreatActorGroup from '../static/images/entities/threat-actor-group.svg';
import ThreatActorIndividual from '../static/images/entities/threat-actor-individual.svg';
import Tool from '../static/images/entities/tool.svg';
import Vulnerability from '../static/images/entities/vulnerability.svg';
import Incident from '../static/images/entities/incident.svg';
import Channel from '../static/images/entities/channel.svg';
import Narrative from '../static/images/entities/narrative.svg';
import Language from '../static/images/entities/language.svg';
import Event from '../static/images/entities/event.svg';
import DataComponent from '../static/images/entities/data-component.svg';
import MalwareAnalysis from '../static/images/entities/malware-analysis.svg';
import DataSource from '../static/images/entities/data-source.svg';
import CaseIncident from '../static/images/entities/case-incident.svg';
import Feedback from '../static/images/entities/feedback.svg';
import CaseRfi from '../static/images/entities/case-rfi.svg';
import CaseRft from '../static/images/entities/case-rft.svg';
import Task from '../static/images/entities/task.svg';
import Unknown from '../static/images/entities/unknown.svg';
import StixCyberObservable from '../static/images/entities/stix-cyber-observable.svg';
import relationship from '../static/images/entities/relationship.svg';
import { itemColor } from './Colors';
import { dateFormat, dayEndDate, daysAfter, daysAgo, jsDate, minutesBefore, minutesBetweenDates, timestamp } from './Time';
import { isDateStringNone, isNone } from '../components/i18n';
import { fileUri } from '../relay/environment';
import { isNotEmptyField } from './utils';
import { defaultDate, getMainRepresentative } from './defaultRepresentatives';

const genImage = (src) => {
  const img = new Image();
  img.src = fileUri(src);
  return img;
};

export const graphImages = {
  'Kill-Chain-Phase': genImage(KillChainPhase),
  'Marking-Definition': genImage(MarkingDefinition),
  'External-Reference': genImage(ExternalReference),
  Label: genImage(Label),
  'Attack-Pattern': genImage(AttackPattern),
  Feedback: genImage(Feedback),
  'Case-Incident': genImage(CaseIncident),
  'Case-Rfi': genImage(CaseRfi),
  'Case-Rft': genImage(CaseRft),
  Task: genImage(Task),
  'Malware-Analysis': genImage(MalwareAnalysis),
  Campaign: genImage(Campaign),
  Note: genImage(Note),
  'Observed-Data': genImage(ObservedData),
  Opinion: genImage(Opinion),
  Report: genImage(Report),
  Grouping: genImage(Grouping),
  'Course-Of-Action': genImage(CourseOfAction),
  Individual: genImage(Individual),
  Organization: genImage(Organization),
  Sector: genImage(Sector),
  System: genImage(System),
  Indicator: genImage(Indicator),
  Infrastructure: genImage(Infrastructure),
  'Intrusion-Set': genImage(IntrusionSet),
  City: genImage(City),
  'Administrative-Area': genImage(AdministrativeArea),
  Country: genImage(Country),
  Region: genImage(Region),
  Position: genImage(Position),
  Malware: genImage(Malware),
  'Threat-Actor-Group': genImage(ThreatActorGroup),
  'Threat-Actor-Individual': genImage(ThreatActorIndividual),
  Tool: genImage(Tool),
  Vulnerability: genImage(Vulnerability),
  Incident: genImage(Incident),
  Channel: genImage(Channel),
  Narrative: genImage(Narrative),
  Language: genImage(Language),
  Event: genImage(Event),
  'Data-Component': genImage(DataComponent),
  'Data-Source': genImage(DataSource),
  'Autonomous-System': genImage(StixCyberObservable),
  Directory: genImage(StixCyberObservable),
  'Domain-Name': genImage(StixCyberObservable),
  'Email-Addr': genImage(StixCyberObservable),
  'Email-Message': genImage(StixCyberObservable),
  'Email-Mime-Part-Type': genImage(StixCyberObservable),
  Artifact: genImage(StixCyberObservable),
  StixFile: genImage(StixCyberObservable),
  'X509-Certificate': genImage(StixCyberObservable),
  'IPv4-Addr': genImage(StixCyberObservable),
  'IPv6-Addr': genImage(StixCyberObservable),
  'Mac-Addr': genImage(StixCyberObservable),
  Mutex: genImage(StixCyberObservable),
  'Network-Traffic': genImage(StixCyberObservable),
  Process: genImage(StixCyberObservable),
  Software: genImage(StixCyberObservable),
  'User-Account': genImage(StixCyberObservable),
  Url: genImage(StixCyberObservable),
  'Windows-Registry-Key': genImage(StixCyberObservable),
  'Windows-Registry-Value-Type': genImage(StixCyberObservable),
  'Cryptographic-Key': genImage(StixCyberObservable),
  'Cryptocurrency-Wallet': genImage(StixCyberObservable),
  Hostname: genImage(StixCyberObservable),
  'User-Agent': genImage(StixCyberObservable),
  'Phone-Number': genImage(StixCyberObservable),
  'Bank-Account': genImage(StixCyberObservable),
  'Payment-Card': genImage(StixCyberObservable),
  'Media-Content': genImage(StixCyberObservable),
  Persona: genImage(StixCyberObservable),
  Text: genImage(StixCyberObservable),
  Credential: genImage(StixCyberObservable),
  'Tracking-Number': genImage(StixCyberObservable),
  relationship: genImage(relationship),
  Unknown: genImage(Unknown),
};

export const graphLevel = {
  'Kill-Chain-Phase': 1,
  'Attack-Pattern': 1,
  Campaign: 1,
  Note: 1,
  'Observed-Data': 1,
  Opinion: 1,
  Report: 1,
  Grouping: 1,
  'Course-Of-Action': 1,
  Individual: 1,
  Organization: 1,
  Sector: 1,
  System: 1,
  Indicator: 1,
  Infrastructure: 1,
  'Intrusion-Set': 1,
  'Administrative-Area': 1,
  City: 1,
  Country: 1,
  Region: 1,
  Position: 1,
  Malware: 1,
  'Malware-Analysis': 1,
  'Threat-Actor-Group': 1,
  'Threat-Actor-Individual': 1,
  Tool: 1,
  Vulnerability: 1,
  Incident: 1,
  Channel: 1,
  Narrative: 1,
  Language: 1,
  Event: 1,
  'Data-Component': 1,
  'Data-Source': 1,
  'Autonomous-System': 1,
  'Case-Incident': 1,
  'Case-Rft': 1,
  'Case-Rfi': 1,
  Task: 1,
  Feedback: 1,
  Directory: 1,
  'Domain-Name': 1,
  'Email-Addr': 1,
  'Email-Message': 1,
  'Email-Mime-Part-Type': 1,
  Artifact: 1,
  StixFile: 1,
  'X509-Certificate': 1,
  'IPv4-Addr': 1,
  'IPv6-Addr': 1,
  'Mac-Addr': 1,
  Mutex: 1,
  'Network-Traffic': 1,
  Process: 1,
  Software: 1,
  'User-Account': 1,
  Url: 1,
  'Windows-Registry-Key': 1,
  'Windows-Registry-Value-Type': 1,
  'Cryptographic-Key': 1,
  'Cryptocurrency-Wallet': 1,
  Hostname: 1,
  'User-Agent': 1,
  Text: 1,
  Credential: 1,
  'Tracking-Number': 1,
  'Phone-Number': 1,
  'Bank-Account': 1,
  'Payment-Card': 1,
  'Media-Content': 1,
  Persona: 1,
  relationship: 1,
  Unknown: 1,
};

export const graphRawImages = {
  'Kill-Chain-Phase': KillChainPhase,
  'Marking-Definition': MarkingDefinition,
  'External-Reference': ExternalReference,
  Label,
  'Attack-Pattern': AttackPattern,
  Campaign,
  Note,
  'Observed-Data': ObservedData,
  Opinion,
  Report,
  Grouping,
  'Course-Of-Action': CourseOfAction,
  Individual,
  Organization,
  Sector,
  System,
  Indicator,
  Infrastructure,
  'Intrusion-Set': IntrusionSet,
  City,
  Country,
  Region,
  Position,
  Malware,
  'Malware-Analysis': MalwareAnalysis,
  'Threat-Actor-Group': ThreatActorGroup,
  'Threat-Actor-Individual': ThreatActorIndividual,
  Tool,
  Vulnerability,
  Incident,
  Channel,
  Narrative,
  Language,
  Event,
  'Data-Component': DataComponent,
  'Data-Source': DataSource,
  'Autonomous-System': StixCyberObservable,
  'Case-Incident': CaseIncident,
  Feedback,
  'Case-Rfi': CaseRfi,
  'Case-Rft': CaseRft,
  Task,
  Directory: StixCyberObservable,
  'Domain-Name': StixCyberObservable,
  'Email-Addr': StixCyberObservable,
  'Email-Message': StixCyberObservable,
  'Email-Mime-Part-Type': StixCyberObservable,
  Artifact: StixCyberObservable,
  StixFile: StixCyberObservable,
  'X509-Certificate': StixCyberObservable,
  'IPv4-Addr': StixCyberObservable,
  'IPv6-Addr': StixCyberObservable,
  'Mac-Addr': StixCyberObservable,
  Mutex: StixCyberObservable,
  'Network-Traffic': StixCyberObservable,
  Process: StixCyberObservable,
  Software: StixCyberObservable,
  'User-Account': StixCyberObservable,
  Url: StixCyberObservable,
  'Windows-Registry-Key': StixCyberObservable,
  'Windows-Registry-Value-Type': StixCyberObservable,
  'Cryptographic-Key': StixCyberObservable,
  'Cryptocurrency-Wallet': StixCyberObservable,
  Hostname: StixCyberObservable,
  'User-Agent': StixCyberObservable,
  Text: StixCyberObservable,
  Credential: StixCyberObservable,
  'Tracking-Number': StixCyberObservable,
  'Phone-Number': StixCyberObservable,
  'Bank-Account': StixCyberObservable,
  'Payment-Card': StixCyberObservable,
  'Media-Content': StixCyberObservable,
  Persona: StixCyberObservable,
  Unknown,
  relationship,
};

export const encodeGraphData = (graphData) => toB64(JSON.stringify(graphData));

export const decodeGraphData = (encodedGraphData) => {
  if (encodedGraphData) {
    const decodedGraphData = JSON.parse(fromB64(encodedGraphData));
    if (typeof decodedGraphData === 'object') {
      return decodedGraphData;
    }
  }
  return {};
};

export const encodeMappingData = (mappingData) => toB64(JSON.stringify(mappingData));

export const decodeMappingData = (encodedMappingData) => {
  if (encodedMappingData) {
    const decodedMappingData = JSON.parse(fromB64(encodedMappingData));
    if (typeof decodedMappingData === 'object') {
      return decodedMappingData;
    }
  }
  return {};
};

export const computeTimeRangeInterval = (objects) => {
  const filteredDates = objects
    .filter(
      (o) => o.parent_types && o.parent_types.includes('basic-relationship'),
    )
    .filter((o) => {
      const n = defaultDate(o);
      return !R.isNil(n) && !isDateStringNone(n);
    })
    .map((n) => jsDate(defaultDate(n)));
  const orderedElementsDate = R.sort((a, b) => a - b, filteredDates);
  let startDate = jsDate(daysAgo(1));
  let endDate = jsDate(dayEndDate());
  if (orderedElementsDate.length >= 1) {
    startDate = jsDate(daysAgo(1, orderedElementsDate[0]));
    endDate = jsDate(daysAfter(1, orderedElementsDate[0]));
  }
  if (orderedElementsDate.length >= 2) {
    endDate = jsDate(daysAfter(1, orderedElementsDate.slice(-1)[0]));
  }
  return [startDate, endDate];
};

export const computeTimeRangeValues = (interval, objects) => {
  const elementsDates = R.map(
    (n) => timestamp(defaultDate(n)),
    R.filter(
      (n) => n.parent_types && n.parent_types.includes('basic-relationship'),
      objects,
    ),
  );
  const minutes = minutesBetweenDates(interval[0], interval[1]);
  const intervalInMinutes = Math.ceil(minutes / 100);
  const intervalInSecondes = intervalInMinutes * 60;
  const intervals = Array(100)
    .fill()
    .map((_, i) => timestamp(minutesBefore(minutes - i * intervalInMinutes, interval[1])));
  return R.map(
    (n) => ({
      time: n,
      index: 1,
      value: R.filter(
        (o) => o >= n && o <= n + intervalInSecondes,
        elementsDates,
      ).length,
    }),
    intervals,
  );
};

const computeFilteredNodesIds = (
  nodesData,
  stixCoreObjectsTypes = [],
  markedBy = [],
  createdBy = [],
  filteredTargetIds = [],
) => nodesData
  .filter(
    (n) => stixCoreObjectsTypes.includes(n.entity_type)
        || R.any((m) => R.includes(m.id, markedBy), n.markedBy)
        || createdBy.includes(n.createdBy.id)
        || filteredTargetIds.includes(n.id),
  )
  .map((n) => n.id);

const computeFilteredLinks = (
  linksData,
  markedBy = [],
  createdBy = [],
  interval = [],
) => linksData.filter(
  (n) => R.any((m) => R.includes(m.id, markedBy), n.markedBy)
      || createdBy.includes(n.createdBy.id)
      || (isNotEmptyField(n.defaultDate)
        && interval.length > 0
        && ((isNotEmptyField(n.start_time) && n.start_time < interval[0])
          || (isNotEmptyField(n.stop_time) && n.stop_time > interval[1])
          || n.defaultDate < interval[0]
          || n.defaultDate > interval[1])),
);

export const applyFilters = (
  graphData,
  stixCoreObjectsTypes = [],
  markedBy = [],
  createdBy = [],
  excludedStixCoreObjectsTypes = [],
  interval = [],
) => {
  const filteredLinks = computeFilteredLinks(
    graphData.links,
    markedBy,
    createdBy,
    interval,
  );
  const filteredLinkIds = filteredLinks.map((n) => n.id);
  const filteredTargetIds = filteredLinks.map((n) => n.target_id);
  const filteredNodesIds = computeFilteredNodesIds(
    graphData.nodes,
    stixCoreObjectsTypes,
    markedBy,
    createdBy,
    filteredTargetIds,
  );
  const nodes = graphData.nodes
    .filter((n) => !excludedStixCoreObjectsTypes.includes(n.entity_type))
    .map((n) => R.assoc('disabled', filteredNodesIds.includes(n.id), n));
  const nodeIds = nodes.map((n) => n.id);
  const links = graphData.links
    .filter(
      (n) => nodeIds.includes(n.source_id) && nodeIds.includes(n.target_id),
    )
    .map((n) => R.assoc('disabled', filteredLinkIds.includes(n.id), n));
  return {
    nodes,
    links,
  };
};

export const buildCorrelationData = (
  originalObjects,
  graphData,
  t,
  filterAdjust,
  key = 'reports',
) => {
  const objects = R.map((n) => {
    let { objectMarking } = n;
    if (R.isNil(objectMarking) || R.isEmpty(objectMarking)) {
      objectMarking = [
        {
          id: 'abb8eb18-a02c-48e9-adae-08c92275c87e',
          definition: t('None'),
          definition_type: t('None'),
        },
      ];
    }
    let { createdBy } = n;
    if (R.isNil(createdBy) || R.isEmpty(createdBy)) {
      createdBy = {
        id: '0533fcc9-b9e8-4010-877c-174343cb24cd',
        name: t('None'),
      };
    }
    return {
      ...n,
      objectMarking,
      createdBy,
      markedBy: objectMarking,
    };
  }, originalObjects);
  const thisReportOriginalNodes = R.filter(
    (o) => o && o.id && o.entity_type && o[key],
    objects,
  );
  const filteredNodesIds = computeFilteredNodesIds(
    thisReportOriginalNodes,
    filterAdjust.stixCoreObjectsTypes,
    filterAdjust.markedBy,
    filterAdjust.createdBy,
  );
  const thisReportNodes = thisReportOriginalNodes.map((n) => R.assoc('disabled', filteredNodesIds.includes(n.id), n));
  const thisReportLinkNodes = R.filter(
    (n) => n[key] && n.parent_types && n[key].edges.length > 1,
    thisReportNodes,
  );
  const relatedReportOriginalNodes = R.pipe(
    R.map((n) => n[key].edges),
    R.flatten,
    R.map((n) => {
      let { objectMarking } = n.node;
      if (R.isNil(objectMarking) || R.isEmpty(objectMarking)) {
        objectMarking = [
          {
            id: 'abb8eb18-a02c-48e9-adae-08c92275c87e',
            definition: t('None'),
            definition_type: t('None'),
          },
        ];
      }
      let { createdBy } = n.node;
      if (R.isNil(createdBy) || R.isEmpty(createdBy)) {
        createdBy = {
          id: '0533fcc9-b9e8-4010-877c-174343cb24cd',
          name: t('None'),
        };
      }
      return {
        ...n.node,
        objectMarking,
        createdBy,
        markedBy: objectMarking,
      };
    }),
    R.uniqBy(R.prop('id')),
    R.map((n) => (n.defaultDate ? { ...n } : { ...n, defaultDate: jsDate(defaultDate(n)) })),
  )(thisReportLinkNodes);
  const relatedReportFilteredNodeIds = computeFilteredNodesIds(
    relatedReportOriginalNodes,
    filterAdjust.stixCoreObjectsTypes,
    filterAdjust.markedBy,
    filterAdjust.createdBy,
  );
  const relatedReportNodes = relatedReportOriginalNodes.map((n) => R.assoc('disabled', relatedReportFilteredNodeIds.includes(n.id), n));
  const links = R.pipe(
    R.map((n) => R.map(
      (e) => ({
        id: R.concat(n.id, '-', e.id),
        parent_types: ['basic-relationship', 'stix-meta-relationship'],
        entity_type: 'basic-relationship',
        relationship_type: 'reported-in',
        source: n.id,
        target: e.id,
        label: '',
        name: '',
        source_id: n.id,
        target_id: e.id,
        from: n.id,
        to: n.id,
        start_time: '',
        stop_time: '',
        defaultDate: jsDate(defaultDate(n)),
        markedBy: n.markedBy,
        createdBy: n.createdBy,
      }),
      R.filter(
        (m) => m
            && R.includes(
              m.id,
              R.map((o) => o.node.id, n[key].edges),
            ),
      )(relatedReportNodes),
    )),
    R.flatten,
  )(thisReportLinkNodes);
  const combinedNodes = R.concat(thisReportLinkNodes, relatedReportNodes);
  const nodes = R.pipe(
    R.map((n) => ({
      id: n.id,
      disabled: n.disabled,
      val: graphLevel[n.entity_type] || graphLevel.Unknown,
      name: getMainRepresentative(n),
      defaultDate: jsDate(defaultDate(n)),
      label: truncate(
        getMainRepresentative(n),
        n.entity_type === 'Attack-Pattern' ? 30 : 20,
      ),
      img: graphImages[n.entity_type] || graphImages.Unknown,
      entity_type: n.entity_type,
      rawImg: graphRawImages[n.entity_type] || graphRawImages.Unknown,
      color: n.x_opencti_color || n.color || itemColor(n.entity_type, false),
      parent_types: n.parent_types,
      isObservable: !!n.observable_value,
      markedBy: n.markedBy,
      createdBy: n.createdBy,
      fx: graphData[n.id] && graphData[n.id].x ? graphData[n.id].x : null,
      fy: graphData[n.id] && graphData[n.id].y ? graphData[n.id].y : null,
    })),
  )(combinedNodes);
  return {
    nodes,
    links,
  };
};

export const buildGraphData = (objects, graphData, t) => {
  const relationshipsIdsInNestedRelationship = R.pipe(
    R.filter(
      (n) => n.from && n.to && (n.from.relationship_type || n.to.relationship_type),
    ),
    R.map((n) => (n.from?.relationship_type ? n.from.id : n.to.id)),
  )(objects);

  const normalLinks = R.pipe(
    R.filter(
      (n) => n.parent_types.includes('basic-relationship')
        && !R.includes(n.id, relationshipsIdsInNestedRelationship)
        && n.from
        && n.to,
    ),
    R.uniqBy(R.prop('id')),
    R.map((n) => ({
      id: n.id,
      disabled: false,
      parent_types: n.parent_types,
      entity_type: n.entity_type,
      relationship_type: n.relationship_type,
      source: n.from.id,
      target: n.to.id,
      label: t(`relationship_${n.entity_type}`),
      name: `<strong>${t(`relationship_${n.entity_type}`)}</strong>\n${t(
        'Created the',
      )} ${dateFormat(n.created)}\n${t('Start time')} ${
        isNone(n.start_time || n.first_seen)
          ? '-'
          : dateFormat(n.start_time || n.first_seen)
      }\n${t('Stop time')} ${
        isNone(n.stop_time || n.last_seen)
          ? '-'
          : dateFormat(n.stop_time || n.last_seen)
      }`,
      source_id: n.from.id,
      target_id: n.to.id,
      inferred: n.is_inferred,
      isNestedInferred:
        (n.types?.includes('inferred') && !n.types.includes('manual')) || false,
      defaultDate: jsDate(defaultDate(n)),
      markedBy:
        !R.isNil(n.objectMarking) && !R.isEmpty(n.objectMarking)
          ? R.map(
            (m) => ({ id: m.id, definition: m.definition }),
            n.objectMarking,
          )
          : [
            {
              id: 'abb8eb18-a02c-48e9-adae-08c92275c87e',
              definition: t('None'),
              definition_type: t('None'),
            },
          ],
      createdBy:
        !R.isNil(n.createdBy) && !R.isEmpty(n.createdBy)
          ? n.createdBy
          : { id: '0533fcc9-b9e8-4010-877c-174343cb24cd', name: t('None') },
    })),
  )(objects);
  const nestedLinks = R.pipe(
    R.filter((n) => R.includes(n.id, relationshipsIdsInNestedRelationship)),
    R.uniqBy(R.prop('id')),
    R.map((n) => [
      {
        id: n.id,
        disabled: false,
        parent_types: n.parent_types,
        entity_type: n.entity_type,
        relationship_type: n.relationship_type,
        inferred: n.is_inferred,
        source: n.from.id,
        target: n.id,
        label: '',
        name: '',
        source_id: n.from.id,
        target_id: n.id,
        start_time: '',
        stop_time: '',
        defaultDate: jsDate(defaultDate(n)),
        markedBy:
          !R.isNil(n.objectMarking) && !R.isEmpty(n.objectMarking)
            ? R.map(
              (m) => ({ id: m.id, definition: m.definition }),
              n.objectMarking,
            )
            : [
              {
                id: 'abb8eb18-a02c-48e9-adae-08c92275c87e',
                definition: t('None'),
                definition_type: t('None'),
              },
            ],
        createdBy:
          !R.isNil(n.createdBy) && !R.isEmpty(n.createdBy)
            ? n.createdBy
            : { id: '0533fcc9-b9e8-4010-877c-174343cb24cd', name: t('None') },
      },
      {
        id: n.id,
        disabled: false,
        parent_types: n.parent_types,
        entity_type: n.entity_type,
        relationship_type: n.relationship_type,
        isNestedInferred:
          (n.types?.includes('inferred') && !n.types.includes('manual'))
          || false,
        source: n.id,
        target: n.to.id,
        label: '',
        name: '',
        source_id: n.id,
        target_id: n.to.id,
        start_time: '',
        stop_time: '',
        defaultDate: jsDate(defaultDate(n)),
        markedBy:
          !R.isNil(n.objectMarking) && !R.isEmpty(n.objectMarking)
            ? R.map(
              (m) => ({ id: m.id, definition: m.definition }),
              n.objectMarking,
            )
            : [
              {
                id: 'abb8eb18-a02c-48e9-adae-08c92275c87e',
                definition: t('None'),
                definition_type: t('None'),
              },
            ],
        createdBy:
          !R.isNil(n.createdBy) && !R.isEmpty(n.createdBy)
            ? n.createdBy
            : { id: '0533fcc9-b9e8-4010-877c-174343cb24cd', name: t('None') },
      },
    ]),
    R.flatten,
  )(objects);
  const links = R.concat(normalLinks, nestedLinks);

  // Map to know how many links are displayed for each node
  const nodesLinksCounter = new Map();
  links.forEach((link) => {
    const from = link.source_id;
    const to = link.target_id;
    if (nodesLinksCounter.has(from)) {
      nodesLinksCounter.set(from, nodesLinksCounter.get(from) + 1);
    } else {
      nodesLinksCounter.set(from, 1);
    }
    if (nodesLinksCounter.has(to)) {
      nodesLinksCounter.set(to, nodesLinksCounter.get(to) + 1);
    } else {
      nodesLinksCounter.set(to, 1);
    }
  });

  const nodes = R.pipe(
    R.filter(
      (n) => !n.parent_types.includes('basic-relationship')
        || R.includes(n.id, relationshipsIdsInNestedRelationship),
    ),
    R.map((n) => R.assoc('number_keys', R.keys(n).length, n)),
    R.sortWith([R.descend(R.prop('number_keys'))]),
    R.uniqBy(R.prop('id')),
    R.map((n) => {
      let numberOfConnectedElement;
      if (n.numberOfConnectedElement !== undefined) {
        // The diff between all connections less the ones displayed in the graph.
        numberOfConnectedElement = n.numberOfConnectedElement - (nodesLinksCounter.get(n.id) ?? 0);
      } else if (
        !n.parent_types.includes('Stix-Meta-Object')
        && !n.parent_types.includes('Identity')
      ) {
        // Keep undefined for Meta and Identity objects to display a '?' while the query
        // to fetch real count is loading.
        numberOfConnectedElement = 0;
      }

      return {
        id: n.id,
        disabled: false,
        val:
          graphLevel[
            n.parent_types.includes('basic-relationship')
              ? 'relationship'
              : n.entity_type
          ] || graphLevel.Unknown,
        name: `${
          n.relationship_type
            ? `<strong>${t(
              `relationship_${n.relationship_type}`,
            )}</strong>\n${t('Created the')} ${dateFormat(n.created)}\n${t(
              'Start time',
            )} ${
              isNone(n.start_time || n.first_seen)
                ? '-'
                : dateFormat(n.start_time || n.first_seen)
            }\n${t('Stop time')} ${
              isNone(n.stop_time || n.last_seen)
                ? '-'
                : dateFormat(n.stop_time || n.last_seen)
            }`
            : getMainRepresentative(n)
        }\n${dateFormat(defaultDate(n))}`,
        defaultDate: jsDate(defaultDate(n)),
        label: n.parent_types.includes('basic-relationship')
          ? t(`relationship_${n.relationship_type}`)
          : truncate(
            getMainRepresentative(n),
            n.entity_type === 'Attack-Pattern' ? 30 : 20,
          ),
        img:
          graphImages[
            n.parent_types.includes('basic-relationship')
              ? 'relationship'
              : n.entity_type
          ] || graphImages.Unknown,
        rawImg:
          graphRawImages[
            n.parent_types.includes('basic-relationship')
              ? 'relationship'
              : n.entity_type
          ] || graphRawImages.Unknown,
        color: n.x_opencti_color || n.color || itemColor(n.entity_type, false),
        parent_types: n.parent_types,
        entity_type: n.entity_type,
        relationship_type: n.relationship_type,
        fromId: n.from?.id,
        fromType: n.from?.entity_type,
        toId: n.to?.id,
        toType: n.to?.entity_type,
        isObservable: !!n.observable_value,
        numberOfConnectedElement,
        isNestedInferred:
          (n.types?.includes('inferred') && !n.types.includes('manual'))
          || false,
        markedBy:
          !R.isNil(n.objectMarking) && !R.isEmpty(n.objectMarking)
            ? R.map(
              (m) => ({ id: m.id, definition: m.definition }),
              n.objectMarking,
            )
            : [
              {
                id: 'abb8eb18-a02c-48e9-adae-08c92275c87e',
                definition: t('None'),
                definition_type: t('None'),
              },
            ],
        createdBy:
          !R.isNil(n.createdBy) && !R.isEmpty(n.createdBy)
            ? n.createdBy
            : { id: '0533fcc9-b9e8-4010-877c-174343cb24cd', name: t('None') },
        fx: graphData[n.id] && graphData[n.id].x ? graphData[n.id].x : null,
        fy: graphData[n.id] && graphData[n.id].y ? graphData[n.id].y : null,
      };
    }),
  )(objects);

  return {
    nodes,
    links,
  };
};

export const nodePaint = (
  colors,
  { label, img, x, y, numberOfConnectedElement },
  color,
  ctx,
  selected = false,
  inferred = false,
  disabled = false,
  showNbConnectedElements = false,
) => {
  ctx.beginPath();
  ctx.fillStyle = disabled ? colors.disabled : color;
  ctx.arc(x, y, 5, 0, 2 * Math.PI, false);
  ctx.fill();

  if (selected) {
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = colors.selected;
    ctx.stroke();
  } else if (inferred) {
    ctx.lineWidth = 0.8;
    ctx.strokeStyle = colors.inferred;
    ctx.stroke();
  }

  const size = 8;
  ctx.drawImage(img, x - size / 2, y - size / 2, size, size);
  ctx.font = '4px IBM Plex Sans';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(label, x, y + 9);

  const validConnectedElements = numberOfConnectedElement === undefined || numberOfConnectedElement > 0;
  if (showNbConnectedElements && validConnectedElements) {
    ctx.beginPath();
    ctx.arc(x + 4, y - 3, 2, 0, 2 * Math.PI, false);
    ctx.lineWidth = 0.4;
    ctx.strokeStyle = color;
    ctx.stroke();
    ctx.fillStyle = colors.numbersBackground;
    ctx.fill();
    ctx.fillStyle = colors.numberText;
    let numberLabel = '?';
    if (numberOfConnectedElement !== undefined) numberLabel = numberOfConnectedElement;
    if (numberLabel !== '?') {
      numberLabel = numberOfConnectedElement > 99 ? '99+' : `${numberLabel}+`;
    }
    ctx.font = '1.5px IBM Plex Sans';
    ctx.fillText(numberLabel, x + 4, y - 2.9);
  }
};

export const nodeAreaPaint = ({ name, x, y }, color, ctx) => {
  ctx.beginPath();
  ctx.fillStyle = color;
  ctx.arc(x, y, 5, 0, 2 * Math.PI, false);
  ctx.fill();
  ctx.font = '4px IBM Plex Sans';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(name, x, y + 10);
};

export const linkPaint = (link, ctx, color) => {
  const start = link.source;
  const end = link.target;
  if (link.disabled || typeof start !== 'object' || typeof end !== 'object') return;
  const textPos = Object.assign(
    ...['x', 'y'].map((c) => ({
      [c]: start[c] + (end[c] - start[c]) / 2,
    })),
  );
  const relLink = { x: end.x - start.x, y: end.y - start.y };
  let textAngle = Math.atan2(relLink.y, relLink.x);
  if (textAngle > Math.PI / 2) textAngle = -(Math.PI - textAngle);
  if (textAngle < -Math.PI / 2) textAngle = -(-Math.PI - textAngle);
  const fontSize = 3;
  ctx.font = `${fontSize}px IBM Plex Sans`;
  ctx.save();
  ctx.translate(textPos.x, textPos.y);
  ctx.rotate(textAngle);
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = color;
  ctx.fillText(link.label, 0, 0);
  ctx.restore();
};

export const nodeThreePaint = (node, color) => {
  const sprite = new SpriteText(node.label);
  sprite.color = color;
  sprite.textHeight = 1.5;
  return sprite;
};

export const parseDomain = (data) => [
  0,
  Math.max.apply(
    null,
    data.map((entry) => entry.value),
  ),
];

export const pointInPolygon = (polygon, point) => {
  // A point is in a polygon if a line from the point to infinity crosses the polygon an odd number of times
  let odd = false;
  // For each edge (In this case for each point of the polygon and the previous one)
  for (let i = 0, j = polygon.length - 1; i < polygon.length; i += 1) {
    // If a line from the point into infinity crosses this edge
    if (
      polygon[i][1] > point[1] !== polygon[j][1] > point[1] // One point needs to be above, one below our y coordinate
      // ...and the edge doesn't cross our Y corrdinate before our x coordinate (but between our x coordinate and infinity)
      && point[0]
        < ((polygon[j][0] - polygon[i][0]) * (point[1] - polygon[i][1]))
          / (polygon[j][1] - polygon[i][1])
          + polygon[i][0]
    ) {
      // Invert odd
      odd = !odd;
    }
    j = i;
  }
  // If the number of crossings was odd, the point is in the polygon
  return odd;
};
