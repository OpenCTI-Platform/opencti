import Language from '../../../static/images/entities/language.svg';
import KillChainPhase from '../../../static/images/entities/kill-chain-phase.svg';
import MarkingDefinition from '../../../static/images/entities/marking-definition.svg';
import Label from '../../../static/images/entities/label.svg';
import ExternalReference from '../../../static/images/entities/external-reference.svg';
import AttackPattern from '../../../static/images/entities/attack-pattern.svg';
import Campaign from '../../../static/images/entities/campaign.svg';
import Note from '../../../static/images/entities/note.svg';
import ObservedData from '../../../static/images/entities/observed-data.svg';
import Opinion from '../../../static/images/entities/opinion.svg';
import Report from '../../../static/images/entities/report.svg';
import Grouping from '../../../static/images/entities/grouping.svg';
import CourseOfAction from '../../../static/images/entities/course-of-action.svg';
import Individual from '../../../static/images/entities/individual.svg';
import Organization from '../../../static/images/entities/organization.svg';
import Sector from '../../../static/images/entities/sector.svg';
import System from '../../../static/images/entities/system.svg';
import Indicator from '../../../static/images/entities/indicator.svg';
import Infrastructure from '../../../static/images/entities/infrastructure.svg';
import IntrusionSet from '../../../static/images/entities/intrusion-set.svg';
import City from '../../../static/images/entities/city.svg';
import AdministrativeArea from '../../../static/images/entities/administrative-area.svg';
import Country from '../../../static/images/entities/country.svg';
import Region from '../../../static/images/entities/region.svg';
import Position from '../../../static/images/entities/position.svg';
import Malware from '../../../static/images/entities/malware.svg';
import ThreatActorGroup from '../../../static/images/entities/threat-actor-group.svg';
import ThreatActorIndividual from '../../../static/images/entities/threat-actor-individual.svg';
import Tool from '../../../static/images/entities/tool.svg';
import Vulnerability from '../../../static/images/entities/vulnerability.svg';
import Incident from '../../../static/images/entities/incident.svg';
import Channel from '../../../static/images/entities/channel.svg';
import Narrative from '../../../static/images/entities/narrative.svg';
import Event from '../../../static/images/entities/event.svg';
import DataComponent from '../../../static/images/entities/data-component.svg';
import MalwareAnalysis from '../../../static/images/entities/malware-analysis.svg';
import DataSource from '../../../static/images/entities/data-source.svg';
import CaseIncident from '../../../static/images/entities/case-incident.svg';
import Feedback from '../../../static/images/entities/feedback.svg';
import CaseRfi from '../../../static/images/entities/case-rfi.svg';
import CaseRft from '../../../static/images/entities/case-rft.svg';
import Task from '../../../static/images/entities/task.svg';
import Unknown from '../../../static/images/entities/unknown.svg';
import StixCyberObservable from '../../../static/images/entities/stix-cyber-observable.svg';
import Relationship from '../../../static/images/entities/relationship.svg';
import { fileUri } from '../../../relay/environment';
import SecurityPlatform from '../../../static/images/entities/security-platform.svg';

interface GraphImage {
  img: HTMLImageElement
  rawImg: string
}

type GraphImages = {
  [key: string]: GraphImage
};

const generateHtmlImageElement = (src: string) => {
  const img = new Image();
  img.src = fileUri(src);
  return img;
};

const GRAPH_IMAGES: GraphImages = {
  'Kill-Chain-Phase': {
    rawImg: KillChainPhase,
    img: generateHtmlImageElement(KillChainPhase),
  },
  'Marking-Definition': {
    rawImg: MarkingDefinition,
    img: generateHtmlImageElement(MarkingDefinition),
  },
  'External-Reference': {
    rawImg: ExternalReference,
    img: generateHtmlImageElement(ExternalReference),
  },
  Label: {
    rawImg: Label,
    img: generateHtmlImageElement(Label),
  },
  'Attack-Pattern': {
    rawImg: AttackPattern,
    img: generateHtmlImageElement(AttackPattern),
  },
  Feedback: {
    rawImg: Feedback,
    img: generateHtmlImageElement(Feedback),
  },
  'Case-Incident': {
    rawImg: CaseIncident,
    img: generateHtmlImageElement(CaseIncident),
  },
  'Case-Rfi': {
    rawImg: CaseRfi,
    img: generateHtmlImageElement(CaseRfi),
  },
  'Case-Rft': {
    rawImg: CaseRft,
    img: generateHtmlImageElement(CaseRft),
  },
  Task: {
    rawImg: Task,
    img: generateHtmlImageElement(Task),
  },
  'Malware-Analysis': {
    rawImg: MalwareAnalysis,
    img: generateHtmlImageElement(MalwareAnalysis),
  },
  Campaign: {
    rawImg: Campaign,
    img: generateHtmlImageElement(Campaign),
  },
  Note: {
    rawImg: Note,
    img: generateHtmlImageElement(Note),
  },
  'Observed-Data': {
    rawImg: ObservedData,
    img: generateHtmlImageElement(ObservedData),
  },
  Opinion: {
    rawImg: Opinion,
    img: generateHtmlImageElement(Opinion),
  },
  Report: {
    rawImg: Report,
    img: generateHtmlImageElement(Report),
  },
  Grouping: {
    rawImg: Grouping,
    img: generateHtmlImageElement(Grouping),
  },
  'Course-Of-Action': {
    rawImg: CourseOfAction,
    img: generateHtmlImageElement(CourseOfAction),
  },
  Individual: {
    rawImg: Individual,
    img: generateHtmlImageElement(Individual),
  },
  Organization: {
    rawImg: Organization,
    img: generateHtmlImageElement(Organization),
  },
  SecurityPlatform: {
    rawImg: SecurityPlatform,
    img: generateHtmlImageElement(SecurityPlatform),
  },
  Sector: {
    rawImg: Sector,
    img: generateHtmlImageElement(Sector),
  },
  System: {
    rawImg: System,
    img: generateHtmlImageElement(System),
  },
  Indicator: {
    rawImg: Indicator,
    img: generateHtmlImageElement(Indicator),
  },
  Infrastructure: {
    rawImg: Infrastructure,
    img: generateHtmlImageElement(Infrastructure),
  },
  'Intrusion-Set': {
    rawImg: IntrusionSet,
    img: generateHtmlImageElement(IntrusionSet),
  },
  City: {
    rawImg: City,
    img: generateHtmlImageElement(City),
  },
  'Administrative-Area': {
    rawImg: AdministrativeArea,
    img: generateHtmlImageElement(AdministrativeArea),
  },
  Country: {
    rawImg: Country,
    img: generateHtmlImageElement(Country),
  },
  Region: {
    rawImg: Region,
    img: generateHtmlImageElement(Region),
  },
  Position: {
    rawImg: Position,
    img: generateHtmlImageElement(Position),
  },
  Malware: {
    rawImg: Malware,
    img: generateHtmlImageElement(Malware),
  },
  'Threat-Actor-Group': {
    rawImg: ThreatActorGroup,
    img: generateHtmlImageElement(ThreatActorGroup),
  },
  'Threat-Actor-Individual': {
    rawImg: ThreatActorIndividual,
    img: generateHtmlImageElement(ThreatActorIndividual),
  },
  Tool: {
    rawImg: Tool,
    img: generateHtmlImageElement(Tool),
  },
  Vulnerability: {
    rawImg: Vulnerability,
    img: generateHtmlImageElement(Vulnerability),
  },
  Incident: {
    rawImg: Incident,
    img: generateHtmlImageElement(Incident),
  },
  Channel: {
    rawImg: Channel,
    img: generateHtmlImageElement(Channel),
  },
  Narrative: {
    rawImg: Narrative,
    img: generateHtmlImageElement(Narrative),
  },
  Language: {
    rawImg: Language,
    img: generateHtmlImageElement(Language),
  },
  Event: {
    rawImg: Event,
    img: generateHtmlImageElement(Event),
  },
  'Data-Component': {
    rawImg: DataComponent,
    img: generateHtmlImageElement(DataComponent),
  },
  'Data-Source': {
    rawImg: DataSource,
    img: generateHtmlImageElement(DataSource),
  },
  'Autonomous-System': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Directory: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Domain-Name': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Email-Addr': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Email-Message': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Email-Mime-Part-Type': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Artifact: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  StixFile: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'X509-Certificate': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'IPv4-Addr': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'IPv6-Addr': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Mac-Addr': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Mutex: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Network-Traffic': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Process: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Software: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'User-Account': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Url: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Windows-Registry-Key': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Windows-Registry-Value-Type': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Cryptographic-Key': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Cryptocurrency-Wallet': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Hostname: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'User-Agent': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Phone-Number': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Bank-Account': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Payment-Card': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Media-Content': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Persona: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'SSH-Key': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Text: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  Credential: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  'Tracking-Number': {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  IMEI: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  ICCID: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  IMSI: {
    rawImg: StixCyberObservable,
    img: generateHtmlImageElement(StixCyberObservable),
  },
  relationship: {
    rawImg: Relationship,
    img: generateHtmlImageElement(Relationship),
  },
  Unknown: {
    rawImg: Unknown,
    img: generateHtmlImageElement(Unknown),
  },
};

export default GRAPH_IMAGES;
