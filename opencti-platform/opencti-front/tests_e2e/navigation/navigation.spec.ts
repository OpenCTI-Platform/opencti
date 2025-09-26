import { Page } from '@playwright/test';
import StixCoreObjectDataTab from 'tests_e2e/model/StixCoreObjectDataTab.pageModel';
import FeedbackDetailsPage from 'tests_e2e/model/feedbackDetails.pageModel';
import ObservedDataPage from 'tests_e2e/model/observedData.pageModel';
import CaseRftPage from 'tests_e2e/model/caseRft.pageModel';
import CaseRftDetailsPage from 'tests_e2e/model/caseRftDetails.pageModel';
import ChannelPage from 'tests_e2e/model/channel.pageModel';
import ToolPage from 'tests_e2e/model/tool.pageModel';
import ToolDetailsPage from 'tests_e2e/model/toolDetails.pageModel';
import VulnerabilityPage from 'tests_e2e/model/vulnerability.pageModel';
import VulnerabilityDetailsPage from 'tests_e2e/model/vulnerabilityDetails.pageModel';
import AttackPatternPage from 'tests_e2e/model/attackPattern.pageModel';
import NarrativePage from 'tests_e2e/model/narrative.pageModel';
import NarrativeDetailsPage from 'tests_e2e/model/narrativeDetails.pageModel';
import DataComponentDetailsPage from 'tests_e2e/model/dataComponentDetails.pageModel';
import DataSourcePage from 'tests_e2e/model/dataSource.pageModel';
import SectorPage from 'tests_e2e/model/sector.pageModel';
import OrganizationPage from 'tests_e2e/model/organization.pageModel';
import OrganizationDetailsPage from 'tests_e2e/model/organizationDetails.pageModel';
import SecurityPlatformDetailsPage from 'tests_e2e/model/securityPlatformDetails.pageModel';
import DataRelationshipsPage from 'tests_e2e/model/dataRelationships.pageModel';
import SettingsActivityPage from 'tests_e2e/model/settingsActivity.pageModel';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import ContainerObservablesPage from '../model/containerObservables.pageModel';
import GroupingsPage from '../model/grouping.pageModel';
import GroupingDetailsPage from '../model/groupingDetails.pageModel';
import MalwareAnalysesPage from '../model/MalwareAnalyses.pageModel';
import MalwareAnalysesDetailsPage from '../model/MalwareAnalysesDetails.pageModel';
import StixCoreObjectHistoryTab from '../model/StixCoreObjectHistoryTab.pageModel';
import ObservablesPage from '../model/observable.pageModel';
import ObservableDetailsPage from '../model/observableDetails.pageModel';
import NotesPage from '../model/note.pageModel';
import NoteDetailsPage from '../model/noteDetails.pageModel';
import StixCoreObjectDataAndHistoryTab from '../model/StixCoreObjectDataAndHistoryTab.pageModel';
import ExternalReferencePage from '../model/externalReference.pageModel';
import ExternalReferenceDetailsPage from '../model/externalReferenceDetails.pageModel';
import IncidentResponsePage from '../model/incidentResponse.pageModel';
import IncidentResponseDetailsPage from '../model/incidentResponseDetails.pageModel';
import CaseRfiPage from '../model/caseRfi.pageModel';
import CaseRfiDetailsPage from '../model/caseRfiDetails.pageModel';
import TaskPage from '../model/tasks.pageModel';
import TaskDetailsPage from '../model/tasksDetails.pageModel';
import FeedbackPage from '../model/feedback.pageModel';
import EventsIncidentPage from '../model/EventsIncident.pageModel';
import EventsIncidentDetailsPage from '../model/EventsIncidentDetails.pageModel';
import SightingsPage from '../model/sightings.pageModel';
import ObservedDataDetailsPage from '../model/observedDataDetails.pageModel';
import ArtifactPage from '../model/Artifact.pageModel';
import StixCoreObjectContentTabPage from '../model/StixCoreObjectContentTab.pageModel';
import IndicatorPage from '../model/indicator.pageModel';
import IndicatorDetailsPageModel from '../model/indicatorDetails.pageModel';
import InfrastructurePage from '../model/infrastructure.pageModel';
import InfrastructureDetailsPageModel from '../model/infrastructureDetails.pageModel';
import ThreatActorGroupPage from '../model/threatActorGroup.pageModel';
import ThreatActorGroupDetailsPage from '../model/threatActorGroupDetails.pageModel';
import ThreatActorIndividualPage from '../model/threatActorIndividual.pageModel';
import ThreatActorIndividualDetailsPage from '../model/threatActorIndividualDetails.pageModel';
import IntrusionSetPage from '../model/intrusionSet.pageModel';
import IntrusionSetDetailsPage from '../model/intrusionSetDetails.pageModel';
import CampaignPageModel from '../model/campaign.pageModel';
import CampaignDetailsPage from '../model/campaignDetails.pageModel';
import MalwarePageModel from '../model/malware.pageModel';
import MalwareDetailsPage from '../model/malwareDetails.pageModel';
import ChannelDetailsPage from '../model/channelDetails.pageModel';
import AttackPatternDetailsPage from '../model/attackPatternDetails.pageModel';
import CourseOfActionPage from '../model/courseOfAction.pageModel';
import CourseOfActionDetailsPage from '../model/courseOfActionDetails.pageModel';
import DataComponentPage from '../model/dataComponent.pageModel';
import DataSourceDetailsPage from '../model/dataSourceDetails.pageModel';
import SectorDetailsPage from '../model/sectorDetails.pageModel';
import EventPage from '../model/events.pageModel';
import EventDetailsPage from '../model/eventDetails.pageModel';
import SecurityPlatformPage from '../model/securityPlatform.pageModel';
import SystemPage from '../model/system.pageModel';
import SystemDetailsPage from '../model/systemDetails.pageModel';
import IndividualPage from '../model/individual.pageModel';
import IndividualDetailsPage from '../model/individualDetails.pageModel';
import RegionPage from '../model/region.pageModel';
import RegionDetailsPage from '../model/regionDetails.pageModel';
import CountryPage from '../model/country.pageModel';
import CountryDetailsPage from '../model/countryDetails.pageModel';
import AdministrativeAreaPage from '../model/administrativeArea.pageModel';
import AdministrativeAreaDetailsPage from '../model/AdministrativeAreaDetails.pageModel';
import CityPage from '../model/city.pageModel';
import CityDetailsPage from '../model/cityDetails.pageModel';
import PositionPage from '../model/position.pageModel';
import PositionDetailsPage from '../model/positionDetails.pageModel';
import DataEntitiesPage from '../model/DataEntities.pageModel';
import DataManagementPage from '../model/dataManagement.pageModel';
import TrashPage from '../model/trash.pageModel';
import IngestionPage from '../model/ingestion.pageModel';
import ImportPage from '../model/dataImport.pageModel';
import ProcessingPage from '../model/dataProcessing.pageModel';
import SharingPage from '../model/dataSharing.pageModel';
import SettingsPage from '../model/settings.pageModel';
import SettingsSecurityPage from '../model/settingsSecurity.pageModel';
import SettingsCustomizationPage from '../model/settingsCustomization.pageModel';
import SettingsTaxonomiesPage from '../model/settingsTaxonomies.pageModel';
import SettingsFileIndexingPage from '../model/settingsFileIndexing.pageModel';
import SettingsFiligranExperiencePage from '../model/settingsFiligranExperience.pageModel';

/**
 * Goal: validate that everything is opening without errors in Analyses > Note.
 * @param page
 */
const navigateNotes = async (page: Page) => {
  const notesNameFromInitData = 'This is my test note.';

  const notePage = new NotesPage(page);
  await notePage.navigateFromMenu();
  await expect(notePage.getPage()).toBeVisible();
  await expect(page.getByText(notesNameFromInitData)).toBeVisible();
  await notePage.getItemFromList(notesNameFromInitData).click();

  const noteDetailsPage = new NoteDetailsPage(page);
  await expect(noteDetailsPage.getPage()).toBeVisible();

  // -- Data
  await noteDetailsPage.tabs.goToDataTab();
  const dataTab = new StixCoreObjectDataTab(page);
  await expect(dataTab.getPage()).toBeVisible();

  // -- History
  await noteDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Analyses > External References.
 * @param page
 */
const navigateExternalReferences = async (page: Page) => {
  const externalReferencesFromInitData = 'Kaspersky Sofacy';

  const externalReferencePage = new ExternalReferencePage(page);
  await externalReferencePage.navigateFromMenu();
  await expect(externalReferencePage.getPage()).toBeVisible();
  await expect(page.getByText(externalReferencesFromInitData)).toBeVisible();
  await externalReferencePage.getItemFromList(externalReferencesFromInitData).click();

  const externalReferenceDetailsPage = new ExternalReferenceDetailsPage(page);
  await expect(externalReferenceDetailsPage.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Analyses > Malware analyses.
 * @param page
 */
const navigateMalwareAnalyses = async (page: Page) => {
  const malwareAnalysesNameFromInitData = 'Spelevo EK analysis';
  const malwareAnalysesPage = new MalwareAnalysesPage(page);
  await malwareAnalysesPage.navigateFromMenu();

  await expect(malwareAnalysesPage.getPage()).toBeVisible();
  await expect(malwareAnalysesPage.getItemFromList(malwareAnalysesNameFromInitData)).toBeVisible();
  await malwareAnalysesPage.getItemFromList(malwareAnalysesNameFromInitData).click();

  const malwareAnalysesDetailsPage = new MalwareAnalysesDetailsPage(page);
  await expect(malwareAnalysesDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await malwareAnalysesDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();
  await page.getByLabel('relationships', { exact: true }).click();
  await expect(page.getByRole('link', { name: 'related to Malware Spelevo EK' })).toBeVisible();
  await page.getByLabel('entities', { exact: true }).click();
  await expect(page.getByRole('link', { name: 'Malware Spelevo EK - admin covid-19' })).toBeVisible();

  // -- Content
  await malwareAnalysesDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Data
  await malwareAnalysesDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await malwareAnalysesDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening wihtout errors in Analyses > Grouping.
 * @param page
 */
const navigateGroupings = async (page: Page) => {
  const groupingsNameFromInitData = 'Navigation test grouping entity';

  const groupingPage = new GroupingsPage(page);
  await groupingPage.navigateFromMenu();
  await expect(groupingPage.getPage()).toBeVisible();
  await expect(page.getByText(groupingsNameFromInitData)).toBeVisible();
  await groupingPage.getItemFromList(groupingsNameFromInitData).click();

  const groupingsDetailsPage = new GroupingDetailsPage(page);
  await expect(groupingsDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await groupingsDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('groupings-knowledge')).toBeVisible();
  await page.getByLabel('Correlation view').click();
  await page.getByLabel('Tactics matrix view').click();
  await page.getByLabel('Graph view').click();

  // -- Content
  await groupingsDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();
  await contentTab.getContentMappingViewButton().click();
  await expect(page.getByRole('button', { name: 'Clear mappings' })).toBeVisible();
  await contentTab.getContentViewButton().click();
  await contentTab.getEditorViewButton().click();
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await groupingsDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Add entity')).toBeVisible();

  // -- Artifact / Observables
  await groupingsDetailsPage.tabs.goToObservablesTab();
  const observablesTab = new ContainerObservablesPage(page);
  await expect(observablesTab.getPage()).toBeVisible();

  // -- Data
  await groupingsDetailsPage.tabs.goToDataTab();
  const dataTab = new StixCoreObjectDataAndHistoryTab(page);
  await expect(dataTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors
 * Content of the test
 * -------------------
 * Go on report
 * view list of report
 * open one report in overview
 * navigate to knowledge
 * navigate to content
 * navigate to entities
 * navigate to observables
 * navigate to data
 * @param page
 */
const navigateReports = async (page: Page) => {
  const reportNameFromInitData = 'E2E dashboard - Report - now';

  const reportPage = new ReportPage(page);
  await reportPage.navigateFromMenu();
  await expect(reportPage.getPage()).toBeVisible();
  await expect(page.getByText(reportNameFromInitData)).toBeVisible();
  await reportPage.getItemFromList(reportNameFromInitData).click();

  const reportDetailsPage = new ReportDetailsPage(page);
  await expect(reportDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await reportDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('report-knowledge')).toBeVisible();
  await page.getByLabel('TimeLine view').click();
  await page.getByLabel('Correlation view').click();
  await page.getByLabel('Tactics matrix view').click();
  await page.getByLabel('Graph view').click();

  // -- Content
  await reportDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();
  await contentTab.getContentMappingViewButton().click();
  await expect(page.getByRole('button', { name: 'Clear mappings' })).toBeVisible();
  await contentTab.getContentViewButton().click();
  await contentTab.getEditorViewButton().click();
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await reportDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Add entity')).toBeVisible();

  // -- Artifact / Observables
  await reportDetailsPage.tabs.goToObservablesTab();
  const observablesTab = new ContainerObservablesPage(page);
  await expect(observablesTab.getPage()).toBeVisible();

  // -- Data
  await reportDetailsPage.tabs.goToDataTab();
  const dataTab = new StixCoreObjectDataAndHistoryTab(page);
  await expect(dataTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Cases > Incident Response.
 * @param page
 */

const navigateIncidentResponse = async (page: Page) => {
  const incidentResponseNameFromInitData = 'Incident Response Name';
  const incidentResponsePage = new IncidentResponsePage(page);
  await incidentResponsePage.navigateFromMenu();

  await expect(incidentResponsePage.getPage()).toBeVisible();
  await expect(incidentResponsePage.getItemFromList(incidentResponseNameFromInitData)).toBeVisible();
  await incidentResponsePage.getItemFromList(incidentResponseNameFromInitData).click();

  const incidentResponseDetailsPage = new IncidentResponseDetailsPage(page);
  await expect(incidentResponseDetailsPage.getIncidentResponseDetailsPage()).toBeVisible();

  // -- Knowledge
  await incidentResponseDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('incident-response-knowledge')).toBeVisible();
  await page.getByLabel('TimeLine view').click();
  await page.getByLabel('Correlation view').click();
  await page.getByLabel('Tactics matrix view').click();
  await page.getByLabel('Graph view').click();

  // -- Content
  await incidentResponseDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();
  await contentTab.getContentMappingViewButton().click();
  await expect(page.getByRole('button', { name: 'Clear mappings' })).toBeVisible();
  await contentTab.getContentViewButton().click();
  await contentTab.getEditorViewButton().click();
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await incidentResponseDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Add entity')).toBeVisible();

  // -- Artifact / Observables
  await incidentResponseDetailsPage.tabs.goToObservablesTab();
  const observablesTab = new ContainerObservablesPage(page);
  await expect(observablesTab.getPage()).toBeVisible();

  // -- Data
  await incidentResponseDetailsPage.tabs.goToDataTab();
  const dataTab = new StixCoreObjectDataAndHistoryTab(page);
  await expect(dataTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Cases > Request for information.
 * @param page
 */

const navigateRfi = async (page: Page) => {
  const rfiNameFromInitData = 'Request For Information Name';
  const caseRfiPage = new CaseRfiPage(page);
  await caseRfiPage.navigateFromMenu();

  await expect(caseRfiPage.getPage()).toBeVisible();
  await expect(caseRfiPage.getItemFromList(rfiNameFromInitData)).toBeVisible();
  await caseRfiPage.getItemFromList(rfiNameFromInitData).click();

  const caseRfiDetailsPage = new CaseRfiDetailsPage(page);
  await expect(caseRfiDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await caseRfiDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('case-rfi-knowledge')).toBeVisible();
  await page.getByLabel('TimeLine view').click();
  await page.getByLabel('Correlation view').click();
  await page.getByLabel('Tactics matrix view').click();
  await page.getByLabel('Graph view').click();

  // -- Content
  await caseRfiDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();
  await contentTab.getContentMappingViewButton().click();
  await expect(page.getByRole('button', { name: 'Clear mappings' })).toBeVisible();
  await contentTab.getContentViewButton().click();
  await contentTab.getEditorViewButton().click();
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await caseRfiDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Add entity')).toBeVisible();

  // -- Artifact / Observables
  await caseRfiDetailsPage.tabs.goToObservablesTab();
  const observablesTab = new ContainerObservablesPage(page);
  await expect(observablesTab.getPage()).toBeVisible();

  // -- Data
  await caseRfiDetailsPage.tabs.goToDataTab();
  const dataTab = new StixCoreObjectDataAndHistoryTab(page);
  await expect(dataTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Cases > Request for takedown.
 * @param page
 */

const navigateRft = async (page: Page) => {
  const rftNameFromInitData = 'Request for takedown Name';
  const caseRftPage = new CaseRftPage(page);
  await caseRftPage.navigateFromMenu();

  await expect(caseRftPage.getPage()).toBeVisible();
  await expect(caseRftPage.getItemFromList(rftNameFromInitData)).toBeVisible();
  await caseRftPage.getItemFromList(rftNameFromInitData).click();

  const caseRftDetailsPage = new CaseRftDetailsPage(page);
  await expect(caseRftDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await caseRftDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('case-rft-knowledge')).toBeVisible();
  await page.getByLabel('TimeLine view').click();
  await page.getByLabel('Correlation view').click();
  await page.getByLabel('Tactics matrix view').click();
  await page.getByLabel('Graph view').click();

  // -- Content
  await caseRftDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();
  await contentTab.getContentMappingViewButton().click();
  await expect(page.getByRole('button', { name: 'Clear mappings' })).toBeVisible();
  await contentTab.getContentViewButton().click();
  await contentTab.getEditorViewButton().click();
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await caseRftDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Add entity')).toBeVisible();

  // -- Artifact / Observables
  await caseRftDetailsPage.tabs.goToObservablesTab();
  const observablesTab = new ContainerObservablesPage(page);
  await expect(observablesTab.getPage()).toBeVisible();

  // -- Data
  await caseRftDetailsPage.tabs.goToDataTab();
  const dataTab = new StixCoreObjectDataAndHistoryTab(page);
  await expect(dataTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Cases > Tasks.
 * @param page
 */

const navigateTasks = async (page: Page) => {
  const taskNameFromInitData = 'Task Name';
  const taskPage = new TaskPage(page);
  await taskPage.navigateFromMenu();

  await expect(taskPage.getPage()).toBeVisible();
  await expect(taskPage.getItemFromList(taskNameFromInitData)).toBeVisible();
  await taskPage.getItemFromList(taskNameFromInitData).click();

  const taskDetailsPage = new TaskDetailsPage(page);
  // -- Content
  await taskDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Data
  await taskDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await taskDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Cases > Feedbacks.
 * @param page
 */

const navigateFeedbacks = async (page: Page) => {
  const feedbackNameFromInitData = 'Feedback Name';
  const feedbackPage = new FeedbackPage(page);
  await feedbackPage.navigateFromMenu();

  await expect(feedbackPage.getPage()).toBeVisible();
  await expect(feedbackPage.getItemFromList(feedbackNameFromInitData)).toBeVisible();
  await feedbackPage.getItemFromList(feedbackNameFromInitData).click();

  const feedbackDetailsPage = new FeedbackDetailsPage(page);
  // -- Content
  await feedbackDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Data
  await feedbackDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await feedbackDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Events > Incidents.
 * @param page
 */

const navigateEventsIncident = async (page: Page) => {
  const eventsIncidentFromInitData = 'Incident Name';
  const eventIncidentPage = new EventsIncidentPage(page);
  await eventIncidentPage.navigateFromMenu();

  await expect(eventIncidentPage.getPage()).toBeVisible();
  await expect(eventIncidentPage.getItemFromList(eventsIncidentFromInitData)).toBeVisible();
  await eventIncidentPage.getItemFromList(eventsIncidentFromInitData).click();

  const eventsIncidentDetailsPage = new EventsIncidentDetailsPage(page);
  await expect(eventsIncidentDetailsPage.getPage()).toBeVisible();

  // - Knowledge
  await eventsIncidentDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('incident-knowledge')).toBeVisible();

  // -- Content
  await eventsIncidentDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await eventsIncidentDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await eventsIncidentDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await eventsIncidentDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Events > Sightings.
 * @param page
 */

const navigateSightings = async (page: Page) => {
  const sightingsNameFromInitData = 'www.one-clap.jp';
  const sightingPage = new SightingsPage(page);
  await sightingPage.navigateFromMenu();

  await expect(sightingPage.getPage()).toBeVisible();
  await expect(sightingPage.getItemFromList(sightingsNameFromInitData)).toBeVisible();
  await sightingPage.getItemFromList(sightingsNameFromInitData).click();

  await expect(page.getByTestId('sighting-overview')).toBeVisible();
};

/**
 * Goal: validate that everything is opening without errors in Events > Observed Data.
 * @param page
 */

const navigateObservedData = async (page: Page) => {
  const observedDataFromInitData = 'Incident Name';
  const observedDataPage = new ObservedDataPage(page);
  await observedDataPage.navigateFromMenu();

  await expect(observedDataPage.getPage()).toBeVisible();
  await expect(observedDataPage.getItemFromList(observedDataFromInitData)).toBeVisible();
  await observedDataPage.getItemFromList(observedDataFromInitData).click();

  const observedDataDetailsPage = new ObservedDataDetailsPage(page);
  await expect(observedDataDetailsPage.getPage()).toBeVisible();

  // - Entities
  await observedDataDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Observables
  await observedDataDetailsPage.tabs.goToObservablesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await observedDataDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await observedDataDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that enrich button is opening without errors in Observations > Observables.
 * @param page
 */
const navigateObservables = async (page: Page) => {
  const observableInitData = '5.6.7.8';

  const observablePage = new ObservablesPage(page);
  await observablePage.navigateFromMenu();
  await expect(observablePage.getPage()).toBeVisible();
  await expect(page.getByText(observableInitData)).toBeVisible();
  await observablePage.getItemFromList(observableInitData).click();

  const observableDetailsPage = new ObservableDetailsPage(page);
  await expect(observableDetailsPage.getPage()).toBeVisible();
  await observableDetailsPage.getEnrichButton().click();
  await expect(page.getByText('Enrichment connectors')).toBeVisible();
  await observableDetailsPage.closeEnrichment();

  // - Knowledge
  await observableDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('observable-knowledge')).toBeVisible();

  // -- Content
  await observableDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();
};

/**
 * Goal: validate that enrich button is opening without errors in Observations > Artifacts.
 * @param page
 */

const navigateArtifact = async (page: Page) => {
  const artifactInitData = '33b839180c40b0e80f722dcfdbe8dfc55d9ed2781ffa7b964b58324bb1e8daccbfa8ab76c3c5c73c8427458939996939a7353bdc56bdd090d15dab02ac6fdc38';
  const artifactPage = new ArtifactPage(page);
  await artifactPage.navigateFromMenu();
  await expect(artifactPage.getPage(artifactInitData)).toBeVisible();
  await expect(page.getByText(artifactInitData)).toBeVisible();
  await artifactPage.getItemFromList(artifactInitData).click();
};

const navigateIndicators = async (page: Page) => {
  const indicatorsInitData = 'www.sheepster.ru';
  const indicatorPage = new IndicatorPage(page);
  await indicatorPage.navigateFromMenu();
  await expect(indicatorPage.getPage()).toBeVisible();
  await expect(page.getByText(indicatorsInitData)).toBeVisible();
  await indicatorPage.getItemFromList(indicatorsInitData).click();

  const indicatorDetailsPage = new IndicatorDetailsPageModel(page);
  await expect(indicatorDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await indicatorDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('indicator-knowledge')).toBeVisible();

  // -- Content
  await indicatorDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await indicatorDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await indicatorDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await indicatorDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await indicatorDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateInfrastructure = async (page: Page) => {
  const infrastructureInitData = 'mynewinfratest';
  const infrastructurePage = new InfrastructurePage(page);
  await infrastructurePage.navigateFromMenu();
  await expect(infrastructurePage.getPage()).toBeVisible();
  await expect(page.getByText(infrastructureInitData)).toBeVisible();
  await infrastructurePage.getItemFromList(infrastructureInitData).click();

  const infrastructureDetailsPage = new InfrastructureDetailsPageModel(page);
  await expect(infrastructureDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await infrastructureDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('infrastructure-knowledge')).toBeVisible();

  // -- Content
  await infrastructureDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await infrastructureDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await infrastructureDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await infrastructureDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateThreatActorGroup = async (page: Page) => {
  const threatActorGroupInitData = 'Disco Team Threat Actor Group';
  const threatActorGroupPage = new ThreatActorGroupPage(page);
  await threatActorGroupPage.navigateFromMenu();
  await expect(threatActorGroupPage.getPage()).toBeVisible();
  await expect(page.getByText(threatActorGroupInitData)).toBeVisible();
  await threatActorGroupPage.getItemFromListWithUrl(threatActorGroupInitData);

  const threatActorGroupDetailsPage = new ThreatActorGroupDetailsPage(page);
  await expect(threatActorGroupDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await threatActorGroupDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('threat-actor-group-knowledge')).toBeVisible();

  // -- Content
  await threatActorGroupDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analysis
  await threatActorGroupDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await threatActorGroupDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await threatActorGroupDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateThreatActorIndividual = async (page: Page) => {
  const threatActorIndividualInitData = 'E2E dashboard - Threat actor - now';
  const threatActorIndividualPage = new ThreatActorIndividualPage(page);
  await threatActorIndividualPage.navigateFromMenu();
  await expect(threatActorIndividualPage.getPage()).toBeVisible();
  await expect(page.getByText(threatActorIndividualInitData)).toBeVisible();
  await threatActorIndividualPage.getItemFromListWithUrl(threatActorIndividualInitData);

  const threatActorIndividualDetailsPage = new ThreatActorIndividualDetailsPage(page);
  await expect(threatActorIndividualDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await threatActorIndividualDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('threat-actor-individual-knowledge')).toBeVisible();

  // -- Content
  await threatActorIndividualDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analysis
  await threatActorIndividualDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await threatActorIndividualDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await threatActorIndividualDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateIntrusionSet = async (page: Page) => {
  const intrusionSetInitData = 'E2E dashboard - Intrusion set - now';
  const intrusionSetPage = new IntrusionSetPage(page);
  await intrusionSetPage.navigateFromMenu();
  await expect(intrusionSetPage.getPage()).toBeVisible();
  await expect(page.getByText(intrusionSetInitData)).toBeVisible();
  await intrusionSetPage.getItemFromList(intrusionSetInitData).click();

  const intrusionSetDetailsPage = new IntrusionSetDetailsPage(page);
  await expect(intrusionSetDetailsPage.getIntrusionSetDetailsPage()).toBeVisible();

  // -- Knowledge
  await intrusionSetDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('intrusionSet-details-page')).toBeVisible();

  // -- Content
  await intrusionSetDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analysis
  await intrusionSetDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await intrusionSetDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await intrusionSetDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateCampaign = async (page: Page) => {
  const campaignInitData = 'A new campaign';
  const campaignPage = new CampaignPageModel(page);
  await campaignPage.navigateFromMenu();
  await expect(campaignPage.getPage()).toBeVisible();
  await expect(page.getByText(campaignInitData)).toBeVisible();
  await campaignPage.getItemFromList(campaignInitData).click();

  const campaignDetailsPage = new CampaignDetailsPage(page);
  await expect(campaignDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await campaignDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('campaign-knowledge-page')).toBeVisible();

  // -- Content
  await campaignDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analysis
  await campaignDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await campaignDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await campaignDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateMalware = async (page: Page) => {
  const malwareInitData = 'E2E dashboard - Malware - now';
  const malwarePage = new MalwarePageModel(page);
  await malwarePage.navigateFromMenu();
  await expect(malwarePage.getPage()).toBeVisible();
  await expect(page.getByText(malwareInitData)).toBeVisible();
  await malwarePage.getItemFromListWithUrl(malwareInitData);

  const malwareDetailsPage = new MalwareDetailsPage(page);
  await expect(malwareDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await malwareDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('malware-knowledge')).toBeVisible();

  // -- Content
  await malwareDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analysis
  await malwareDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await malwareDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await malwareDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateChannel = async (page: Page) => {
  const channelInitData = 'channel e2e';
  const channelPage = new ChannelPage(page);
  await channelPage.navigateFromMenu();
  await expect(channelPage.getPage()).toBeVisible();
  await expect(page.getByText(channelInitData)).toBeVisible();
  await channelPage.getItemFromList(channelInitData).click();

  const channelDetailsPage = new ChannelDetailsPage(page);
  await expect(channelDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await channelDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('channel-knowledge')).toBeVisible();

  // -- Content
  await channelDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analysis
  await channelDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await channelDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- channelDetailsPage
  await channelDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateTool = async (page: Page) => {
  const toolInitData = 'tool e2e';
  const toolPage = new ToolPage(page);
  await toolPage.navigateFromMenu();
  await expect(toolPage.getPage()).toBeVisible();
  await expect(page.getByText(toolInitData)).toBeVisible();
  await toolPage.getItemFromList(toolInitData).click();

  const toolDetailsPage = new ToolDetailsPage(page);
  await expect(toolDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await toolDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('tool-knowledge')).toBeVisible();

  // -- Content
  await toolDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await toolDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await toolDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await toolDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateVulnerability = async (page: Page) => {
  const vulnerabilityInitData = 'E2E dashboard - Vulnerability - now';
  const vulnerabilityPage = new VulnerabilityPage(page);
  await vulnerabilityPage.navigateFromMenu();
  await expect(vulnerabilityPage.getPage()).toBeVisible();
  await expect(page.getByText(vulnerabilityInitData)).toBeVisible();
  await vulnerabilityPage.getItemFromList(vulnerabilityInitData).click();

  const vulnerabilityDetailsPage = new VulnerabilityDetailsPage(page);
  await expect(vulnerabilityDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await vulnerabilityDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('vulnerability-knowledge')).toBeVisible();

  // -- Content
  await vulnerabilityDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await vulnerabilityDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await vulnerabilityDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await vulnerabilityDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateAttackPattern = async (page: Page) => {
  const attackPatternInitData = 'Attack pattern e2e';
  const attackPatternPage = new AttackPatternPage(page);
  await attackPatternPage.navigateFromMenu();
  await expect(attackPatternPage.getPage()).toBeVisible();
  await expect(page.getByText(attackPatternInitData)).toBeVisible();
  await attackPatternPage.getItemFromList(attackPatternInitData).click();

  const attackPatternDetailsPage = new AttackPatternDetailsPage(page);
  await expect(attackPatternDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await attackPatternDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('attack-pattern-knowledge')).toBeVisible();

  // -- Content
  await attackPatternDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await attackPatternDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await attackPatternDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await attackPatternDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateNarrative = async (page: Page) => {
  const narrativeInitData = 'Narrative e2e';
  const narrativePage = new NarrativePage(page);
  await narrativePage.navigateFromMenu();
  await expect(narrativePage.getPage()).toBeVisible();
  await expect(page.getByText(narrativeInitData)).toBeVisible();
  await narrativePage.getItemFromList(narrativeInitData).click();

  const narrativeDetailsPage = new NarrativeDetailsPage(page);
  await expect(narrativeDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await narrativeDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('narrative-knowledge')).toBeVisible();

  // -- Content
  await narrativeDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await narrativeDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await narrativeDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await narrativeDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateCourseOfAction = async (page: Page) => {
  const courseOfActionInitData = 'Course of action e2e';
  const courseOfActionPage = new CourseOfActionPage(page);
  await courseOfActionPage.navigateFromMenu();
  await expect(courseOfActionPage.getPage()).toBeVisible();
  await expect(page.getByText(courseOfActionInitData)).toBeVisible();
  await courseOfActionPage.getItemFromList(courseOfActionInitData).click();

  const courseOfActionDetailsPage = new CourseOfActionDetailsPage(page);
  await expect(courseOfActionDetailsPage.getPage()).toBeVisible();

  // -- Content
  await courseOfActionDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Data
  await courseOfActionDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await courseOfActionDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateDataComponent = async (page: Page) => {
  const dataComponentInitData = 'Data component e2e';
  const dataComponentPage = new DataComponentPage(page);
  await dataComponentPage.navigateFromMenu();
  await expect(dataComponentPage.getPage()).toBeVisible();
  await expect(page.getByText(dataComponentInitData)).toBeVisible();
  await dataComponentPage.getItemFromList(dataComponentInitData).click();

  const dataComponentDetailsPage = new DataComponentDetailsPage(page);
  await expect(dataComponentDetailsPage.getPage()).toBeVisible();

  // -- Content
  await dataComponentDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Data
  await dataComponentDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await dataComponentDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateDataSource = async (page: Page) => {
  const dataSourceInitData = 'Data source e2e';
  const dataSourcePage = new DataSourcePage(page);
  await dataSourcePage.navigateFromMenu();
  await expect(dataSourcePage.getPage()).toBeVisible();
  await expect(page.getByText(dataSourceInitData)).toBeVisible();
  await dataSourcePage.getItemFromList(dataSourceInitData).click();

  const dataSourceDetailsPage = new DataSourceDetailsPage(page);
  await expect(dataSourceDetailsPage.getPage()).toBeVisible();

  // -- Content
  await dataSourceDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Data
  await dataSourceDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await dataSourceDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateSector = async (page: Page) => {
  const sectorInitData = 'Sector e2e';
  const sectorPage = new SectorPage(page);
  await sectorPage.navigateFromMenu();
  await expect(sectorPage.getPage()).toBeVisible();
  await expect(page.getByText(sectorInitData)).toBeVisible();
  await sectorPage.getItemFromList(sectorInitData).click();

  const sectorDetailsPage = new SectorDetailsPage(page);
  await expect(sectorDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await sectorDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('sector-knowledge')).toBeVisible();

  // -- Content
  await sectorDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await sectorDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await sectorDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await sectorDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await sectorDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateEvent = async (page: Page) => {
  const eventInitData = 'Event e2e';
  const eventPage = new EventPage(page);
  await eventPage.navigateFromMenu();
  await expect(eventPage.getPage()).toBeVisible();
  await expect(page.getByText(eventInitData)).toBeVisible();
  await eventPage.getItemFromList(eventInitData).click();

  const eventDetailsPage = new EventDetailsPage(page);
  await expect(eventDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await eventDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('event-knowledge')).toBeVisible();

  // -- Content
  await eventDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await eventDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await eventDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await eventDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await eventDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateOrganization = async (page: Page) => {
  const organizationInitData = 'Organization e2e';
  const organizationPage = new OrganizationPage(page);
  await organizationPage.navigateFromMenu();
  await expect(organizationPage.getPage()).toBeVisible();
  await expect(page.getByText(organizationInitData)).toBeVisible();
  await organizationPage.getItemFromList(organizationInitData).click();

  const organizationDetailsPage = new OrganizationDetailsPage(page);
  await expect(organizationDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await organizationDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('organization-knowledge')).toBeVisible();

  // -- Content
  await organizationDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await organizationDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await organizationDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await organizationDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await organizationDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateSecurityPlatform = async (page: Page) => {
  const securityPlatformInitData = 'E2e EDR';
  const securityPlatformPage = new SecurityPlatformPage(page);
  await securityPlatformPage.navigateFromMenu();
  await expect(securityPlatformPage.getPage()).toBeVisible();
  await expect(page.getByText(securityPlatformInitData)).toBeVisible();
  await securityPlatformPage.getItemFromList(securityPlatformInitData).click();

  const securityPlatformDetailsPage = new SecurityPlatformDetailsPage(page);
  await expect(securityPlatformDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await securityPlatformDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('security-platform-knowledge')).toBeVisible();

  // -- Content
  await securityPlatformDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await securityPlatformDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Data
  await securityPlatformDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await securityPlatformDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateSystem = async (page: Page) => {
  const systemInitData = 'System e2e';
  const systemPage = new SystemPage(page);
  await systemPage.navigateFromMenu();
  await expect(systemPage.getPage()).toBeVisible();
  await expect(page.getByText(systemInitData)).toBeVisible();
  await systemPage.getItemFromList(systemInitData).click();

  const systemDetailsPage = new SystemDetailsPage(page);
  await expect(systemDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await systemDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('system-knowledge')).toBeVisible();

  // -- Content
  await systemDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await systemDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await systemDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await systemDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await systemDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateIndividual = async (page: Page) => {
  const individualInitData = 'Individual e2e';
  const individualPage = new IndividualPage(page);
  await individualPage.navigateFromMenu();
  await expect(individualPage.getPage()).toBeVisible();
  await expect(page.getByText(individualInitData)).toBeVisible();
  await individualPage.getItemFromList(individualInitData).click();

  const individualDetailsPage = new IndividualDetailsPage(page);
  await expect(individualDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await individualDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('individual-knowledge')).toBeVisible();

  // -- Content
  await individualDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await individualDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await individualDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await individualDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await individualDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateRegion = async (page: Page) => {
  const regionInitData = 'Region e2e';
  const regionPage = new RegionPage(page);
  await regionPage.navigateFromMenu();
  await expect(regionPage.getPage()).toBeVisible();
  await expect(page.getByText(regionInitData)).toBeVisible();
  await regionPage.getItemFromList(regionInitData).click();

  const regionDetailsPage = new RegionDetailsPage(page);
  await expect(regionDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await regionDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('region-knowledge')).toBeVisible();

  // -- Content
  await regionDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await regionDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await regionDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await regionDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await regionDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateCountry = async (page: Page) => {
  const countryInitData = 'Country e2e';
  const countryPage = new CountryPage(page);
  await countryPage.navigateFromMenu();
  await expect(countryPage.getPage()).toBeVisible();
  await expect(page.getByText(countryInitData)).toBeVisible();
  await countryPage.getItemFromList(countryInitData).click();

  const countryDetailsPage = new CountryDetailsPage(page);
  await expect(countryDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await countryDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('country-knowledge')).toBeVisible();

  // -- Content
  await countryDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await countryDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await countryDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await countryDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await countryDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateAdministrativeArea = async (page: Page) => {
  const administrativeAreaInitData = 'Administrative area e2e';
  const administrativeAreaPage = new AdministrativeAreaPage(page);
  await administrativeAreaPage.navigateFromMenu();
  await expect(administrativeAreaPage.getPage()).toBeVisible();
  await expect(page.getByText(administrativeAreaInitData)).toBeVisible();
  await administrativeAreaPage.getItemFromList(administrativeAreaInitData).click();

  const administrativeAreaDetailsPage = new AdministrativeAreaDetailsPage(page);
  await expect(administrativeAreaDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await administrativeAreaDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('administrative-area-knowledge')).toBeVisible();

  // -- Content
  await administrativeAreaDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await administrativeAreaDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await administrativeAreaDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await administrativeAreaDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await administrativeAreaDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateCity = async (page: Page) => {
  const cityInitData = 'City e2e';
  const cityPage = new CityPage(page);
  await cityPage.navigateFromMenu();
  await expect(cityPage.getPage()).toBeVisible();
  await expect(page.getByText(cityInitData)).toBeVisible();
  await cityPage.getItemFromList(cityInitData).click();

  const cityDetailsPage = new CityDetailsPage(page);
  await expect(cityDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await cityDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('city-knowledge')).toBeVisible();

  // -- Content
  await cityDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await cityDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await cityDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await cityDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await cityDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigatePosition = async (page: Page) => {
  const positionInitData = 'Position e2e';
  const positionPage = new PositionPage(page);
  await positionPage.navigateFromMenu();
  await expect(positionPage.getPage()).toBeVisible();
  await expect(page.getByText(positionInitData)).toBeVisible();
  await positionPage.getItemFromList(positionInitData).click();

  const positionDetailsPage = new PositionDetailsPage(page);
  await expect(positionDetailsPage.getPage()).toBeVisible();

  // -- Knowledge
  await positionDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByTestId('position-knowledge')).toBeVisible();

  // -- Content
  await positionDetailsPage.tabs.goToContentTab();
  const contentTab = new StixCoreObjectContentTabPage(page);
  await expect(contentTab.getPage()).toBeVisible();

  // -- Analyses
  await positionDetailsPage.tabs.goToAnalysesTab();
  await expect(page.getByPlaceholder('Search these results...')).toBeVisible();

  // -- Sightings
  await positionDetailsPage.tabs.goToSightingsTab();
  await expect(page.getByTestId('sightings-overview')).toBeVisible();

  // -- Data
  await positionDetailsPage.tabs.goToDataTab();
  await expect(page.getByRole('heading', { name: 'Uploaded files' })).toBeVisible();

  // -- History
  await positionDetailsPage.tabs.goToHistoryTab();
  const historyTab = new StixCoreObjectHistoryTab(page);
  await expect(historyTab.getPage()).toBeVisible();
};

const navigateDataEntities = async (page: Page) => {
  const dataEntitiesPage = new DataEntitiesPage(page);
  await dataEntitiesPage.navigateFromMenu();
  await expect(dataEntitiesPage.getPage()).toBeVisible();
};

const navigateDataRelationships = async (page: Page) => {
  const dataRelationshipsPage = new DataRelationshipsPage(page);
  await dataRelationshipsPage.navigateFromMenu();
  await expect(dataRelationshipsPage.getPage()).toBeVisible();
};

const navigateIngestion = async (page: Page) => {
  const ingestionPage = new IngestionPage(page);
  await ingestionPage.navigateFromMenu();
  await expect(ingestionPage.getIngestionPages('connectors-page')).toBeVisible();
  await ingestionPage.navigateRightMenu('Connector catalog');
  await expect(ingestionPage.getIngestionPages('catalog-page')).toBeVisible();
  await ingestionPage.navigateRightMenu('OpenCTI Streams');
  await expect(ingestionPage.getIngestionPages('streams-page')).toBeVisible();
  await ingestionPage.navigateRightMenu('TAXII Feeds');
  await expect(ingestionPage.getIngestionPages('taxii-feeds-page')).toBeVisible();
  await ingestionPage.navigateRightMenu('TAXII Push');
  await expect(ingestionPage.getIngestionPages('taxii-push-page')).toBeVisible();
  await ingestionPage.navigateRightMenu('RSS Feeds');
  await expect(ingestionPage.getIngestionPages('rss-feeds-page')).toBeVisible();
  await ingestionPage.navigateRightMenu('CSV Feeds');
  await expect(ingestionPage.getIngestionPages('csv-feeds-page')).toBeVisible();
  await ingestionPage.navigateRightMenu('JSON Feeds');
  await expect(ingestionPage.getIngestionPages('json-feeds-page')).toBeVisible();
};

const navigateDataImport = async (page: Page) => {
  const dataImportPage = new ImportPage(page);
  await dataImportPage.navigateFromMenu();
  await expect(dataImportPage.getImportPages('file-page')).toBeVisible();
  await dataImportPage.navigateBreadcrumbs('Drafts');
  await expect(dataImportPage.getImportPages('draft-page')).toBeVisible();
  await dataImportPage.navigateBreadcrumbs('Analyst workbenches');
  await expect(dataImportPage.getImportPages('workbench-page')).toBeVisible();
};

const navigateProcessing = async (page: Page) => {
  const processingPage = new ProcessingPage(page);
  await processingPage.navigateFromMenu();
  await expect(processingPage.getProcessingPages('playbook-page')).toBeVisible();
  await processingPage.navigateRightMenu('Tasks');
  await expect(processingPage.getProcessingPages('processing-tasks-page')).toBeVisible();
  await processingPage.navigateRightMenu('CSV Mappers');
  await expect(processingPage.getProcessingPages('csv-mapper-page')).toBeVisible();
  await processingPage.navigateRightMenu('JSON Mappers');
  await expect(processingPage.getProcessingPages('json-mapper-page')).toBeVisible();
};

const navigateDataSharing = async (page: Page) => {
  const dataSharingPage = new SharingPage(page);
  await dataSharingPage.navigateFromMenu();
  await expect(dataSharingPage.getDataSharingPages('sharing-streams-page')).toBeVisible();
  await dataSharingPage.navigateRightMenu('CSV feeds');
  await expect(dataSharingPage.getDataSharingPages('data-sharing-csv-feeds-page')).toBeVisible();
  await dataSharingPage.navigateRightMenu('TAXII collections');
  await expect(dataSharingPage.getDataSharingPages('taxii-collections-page')).toBeVisible();
};

const navigateDataManagement = async (page: Page) => {
  const dataManagementPage = new DataManagementPage(page);
  await dataManagementPage.navigateFromMenu();
  await expect(dataManagementPage.getPage()).toBeVisible();
};

const navigateTrash = async (page: Page) => {
  const trashPage = new TrashPage(page);
  await trashPage.navigateFromMenu();
  await expect(trashPage.getPage()).toBeVisible();
};

const navigateSettings = async (page: Page) => {
  const settingsPage = new SettingsPage(page);
  await settingsPage.navigateFromMenu();
  await expect(settingsPage.getPage()).toBeVisible();
};

const navigateSecurity = async (page: Page) => {
  const securityPage = new SettingsSecurityPage(page);
  await securityPage.navigateFromMenu();
  await expect(securityPage.getSecurityPages('roles-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Groups');
  await expect(securityPage.getSecurityPages('groups-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Users');
  await expect(securityPage.getSecurityPages('users-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Organizations');
  await expect(securityPage.getSecurityPages('orga-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Sessions');
  await expect(securityPage.getSecurityPages('session-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Policies');
  await expect(securityPage.getSecurityPages('policies-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Marking definitions');
  await expect(securityPage.getSecurityPages('marking-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Dissemination list');
  await expect(securityPage.getSecurityPages('dissemination-settings-page')).toBeVisible();
  await securityPage.navigateRightMenu('Email templates');
  await expect(securityPage.getSecurityPages('email-templates-page')).toBeVisible();
};

const navigateCustomization = async (page: Page) => {
  const customizationPage = new SettingsCustomizationPage(page);
  await customizationPage.navigateFromMenu();
  await expect(customizationPage.getCustomizationPages('subtypes-page')).toBeVisible();
  await customizationPage.getItemFromList('Area').click();
  await expect(page.getByRole('heading', { name: 'Area' })).toBeVisible();
  await customizationPage.navigateRightMenu('Rules engine');
  await expect(customizationPage.getCustomizationPages('rules-page')).toBeVisible();
  await customizationPage.navigateRightMenu('Notifiers');
  await expect(customizationPage.getCustomizationPages('notifiers-page')).toBeVisible();
  await customizationPage.navigateRightMenu('Retention policies');
  await expect(customizationPage.getCustomizationPages('retention-page')).toBeVisible();
  await customizationPage.navigateRightMenu('Decay rules');
  await expect(customizationPage.getCustomizationPages('decay-rules-page')).toBeVisible();
  await customizationPage.navigateRightMenu('Fintel design');
  await expect(customizationPage.getCustomizationPages('fintel-designs-page')).toBeVisible();
  await customizationPage.navigateRightMenu('Exclusion lists');
  await expect(customizationPage.getCustomizationPages('exclusion-lists-page')).toBeVisible();
};

const navigateTaxonomies = async (page: Page) => {
  const taxonomiesPage = new SettingsTaxonomiesPage(page);
  await taxonomiesPage.navigateFromMenu();
  await expect(taxonomiesPage.getTaxonomiesPages('labels-page')).toBeVisible();
  await taxonomiesPage.navigateRightMenu('Kill chain phases');
  await expect(taxonomiesPage.getTaxonomiesPages('kill-chain-phases-page')).toBeVisible();
  await taxonomiesPage.navigateRightMenu('Vocabularies');
  await expect(taxonomiesPage.getTaxonomiesPages('vocabularies-page')).toBeVisible();
  await taxonomiesPage.navigateRightMenu('Status templates');
  await expect(taxonomiesPage.getTaxonomiesPages('status-template-page')).toBeVisible();
  await taxonomiesPage.navigateRightMenu('Case templates');
  await expect(taxonomiesPage.getTaxonomiesPages('case-template-page')).toBeVisible();
};

const navigateActivity = async (page: Page) => {
  const activityPage = new SettingsActivityPage(page);
  await activityPage.navigateFromMenu();
  await expect(activityPage.getActivityPages('audit-page')).toBeVisible();
  await activityPage.navigateRightMenu('Configuration');
  await expect(activityPage.getActivityPages('configuration-page')).toBeVisible();
  await activityPage.navigateRightMenu('Alerting');
  await expect(activityPage.getActivityPages('alerting-page')).toBeVisible();
};

const navigateFileIndexing = async (page: Page) => {
  const fileIndexingPage = new SettingsFileIndexingPage(page);
  await fileIndexingPage.navigateFromMenu();
  await expect(fileIndexingPage.getPage('file-indexing-page')).toBeVisible();
};

const navigateExperience = async (page: Page) => {
  const filigranExperiencePage = new SettingsFiligranExperiencePage(page);
  await filigranExperiencePage.navigateFromMenu();
  await expect(filigranExperiencePage.getPage('experience-page')).toBeVisible();
};

const navigateAllMenu = async (page: Page) => {
  const leftBarPage = new LeftBarPage(page);

  // Checking Analyses menu
  await leftBarPage.clickOnMenu('Analyses', 'Reports');
  await leftBarPage.expectBreadcrumb('Analyses', 'Reports');
  await leftBarPage.clickOnMenu('Analyses', 'Groupings');
  await leftBarPage.expectBreadcrumb('Analyses', 'Groupings');
  await leftBarPage.clickOnMenu('Analyses', 'Malware analyses');
  await leftBarPage.expectBreadcrumb('Analyses', 'Malware analyses');
  await leftBarPage.clickOnMenu('Analyses', 'Notes');
  await leftBarPage.expectBreadcrumb('Analyses', 'Notes');
  await leftBarPage.clickOnMenu('Analyses', 'External references');
  await leftBarPage.expectBreadcrumb('Analyses', 'External references');

  // Checking Cases menu
  await leftBarPage.clickOnMenu('Cases', 'Incident responses');
  await leftBarPage.expectBreadcrumb('Cases', 'Incident responses');
  await leftBarPage.clickOnMenu('Cases', 'Requests for information');
  await leftBarPage.expectBreadcrumb('Cases', 'Requests for information');
  await leftBarPage.clickOnMenu('Cases', 'Requests for takedown');
  await leftBarPage.expectBreadcrumb('Cases', 'Requests for takedown');
  await leftBarPage.clickOnMenu('Cases', 'Tasks');
  await leftBarPage.expectBreadcrumb('Cases', 'Tasks');
  await leftBarPage.clickOnMenu('Cases', 'Requests for takedown');
  await leftBarPage.expectBreadcrumb('Cases', 'Requests for takedown');

  // Checking Events menu
  await leftBarPage.clickOnMenu('Events', 'Incidents');
  await leftBarPage.expectBreadcrumb('Events', 'Incidents');
  await leftBarPage.clickOnMenu('Events', 'Sightings');
  await leftBarPage.expectBreadcrumb('Events', 'Sightings');
  await leftBarPage.clickOnMenu('Events', 'Observed data');
  await leftBarPage.expectBreadcrumb('Events', 'Observed data');

  // Checking Observations menu
  await leftBarPage.clickOnMenu('Observations', 'Observables');
  await leftBarPage.expectBreadcrumb('Observations', 'Observables');
  await leftBarPage.clickOnMenu('Observations', 'Artifacts');
  await leftBarPage.expectBreadcrumb('Observations', 'Artifacts');
  await leftBarPage.clickOnMenu('Observations', 'Indicators');
  await leftBarPage.expectBreadcrumb('Observations', 'Indicators');
  await leftBarPage.clickOnMenu('Observations', 'Infrastructures');
  await leftBarPage.expectBreadcrumb('Observations', 'Infrastructures');

  // Checking Threats menu
  await leftBarPage.clickOnMenu('Threats', 'Threat actors (group)');
  await leftBarPage.expectBreadcrumb('Threats', 'Threat actors (group)');
  await leftBarPage.clickOnMenu('Threats', 'Threat actors (individual)');
  await leftBarPage.expectBreadcrumb('Threats', 'Threat actors (individual)');
  await leftBarPage.clickOnMenu('Threats', 'Intrusion sets');
  await leftBarPage.expectBreadcrumb('Threats', 'Intrusion sets');
  await leftBarPage.clickOnMenu('Threats', 'Campaigns');
  await leftBarPage.expectBreadcrumb('Threats', 'Campaigns');

  // Checking Arsenal menu
  await leftBarPage.clickOnMenu('Arsenal', 'Malware');
  await leftBarPage.expectBreadcrumb('Arsenal', 'Malware');
  await leftBarPage.clickOnMenu('Arsenal', 'Channels');
  await leftBarPage.expectBreadcrumb('Arsenal', 'Channels');
  await leftBarPage.clickOnMenu('Arsenal', 'Tools');
  await leftBarPage.expectBreadcrumb('Arsenal', 'Tools');
  await leftBarPage.clickOnMenu('Arsenal', 'Vulnerabilities');
  await leftBarPage.expectBreadcrumb('Arsenal', 'Vulnerabilities');

  // Checking Techniques menu
  await leftBarPage.clickOnMenu('Techniques', 'Attack patterns');
  await leftBarPage.expectBreadcrumb('Techniques', 'Attack patterns');
  await leftBarPage.clickOnMenu('Techniques', 'Narratives');
  await leftBarPage.expectBreadcrumb('Techniques', 'Narratives');
  await leftBarPage.clickOnMenu('Techniques', 'Courses of action');
  await leftBarPage.expectBreadcrumb('Techniques', 'Courses of action');
  await leftBarPage.clickOnMenu('Techniques', 'Data components');
  await leftBarPage.expectBreadcrumb('Techniques', 'Data components');
  await leftBarPage.clickOnMenu('Techniques', 'Data sources');
  await leftBarPage.expectBreadcrumb('Techniques', 'Data sources');

  // Checking Entities menu
  await leftBarPage.clickOnMenu('Entities', 'Sectors');
  await leftBarPage.expectBreadcrumb('Entities', 'Sectors');
  // await leftBarPage.expectBreadcrumb('Entities', 'Events'); <-- COMPLEX FOR NOW BECAUSE WE HAVE TWO MENUS WITH THE SAME NAME
  await leftBarPage.clickOnMenu('Entities', 'Organizations');
  await leftBarPage.expectBreadcrumb('Entities', 'Organizations');
  await leftBarPage.clickOnMenu('Entities', 'Systems');
  await leftBarPage.expectBreadcrumb('Entities', 'Systems');
  await leftBarPage.clickOnMenu('Entities', 'Individuals');
  await leftBarPage.expectBreadcrumb('Entities', 'Individuals');

  // Checking Locations menu
  await leftBarPage.clickOnMenu('Locations', 'Regions');
  await leftBarPage.expectBreadcrumb('Locations', 'Regions');
  await leftBarPage.clickOnMenu('Locations', 'Countries');
  await leftBarPage.expectBreadcrumb('Locations', 'Countries');
  await leftBarPage.clickOnMenu('Locations', 'Administrative areas');
  await leftBarPage.expectBreadcrumb('Locations', 'Administrative areas');
  await leftBarPage.clickOnMenu('Locations', 'Cities');
  await leftBarPage.expectBreadcrumb('Locations', 'Cities');
  await leftBarPage.clickOnMenu('Locations', 'Positions');
  await leftBarPage.expectBreadcrumb('Locations', 'Positions');

  // Checking Dashboards menu
  await leftBarPage.clickOnMenu('Dashboards', 'Custom dashboards');
  await leftBarPage.expectBreadcrumb('Dashboards', 'Custom dashboards');
  await leftBarPage.clickOnMenu('Dashboards', 'Public dashboards');
  await leftBarPage.expectBreadcrumb('Dashboards', 'Public dashboards');

  // Checking Data menu
  // await leftBarPage.expectBreadcrumb('Data', 'Entities'); <-- COMPLEX FOR NOW BECAUSE WE HAVE TWO MENUS WITH THE SAME NAME
  await leftBarPage.clickOnMenu('Data', 'Relationships');
  await leftBarPage.expectBreadcrumb('Data', 'Relationships');
  await leftBarPage.clickOnMenu('Data', 'Ingestion');
  await leftBarPage.expectBreadcrumb('Data', 'Ingestion');
  await leftBarPage.clickOnMenu('Data', 'Import');
  await leftBarPage.expectBreadcrumb('Data', 'Import');
  await leftBarPage.clickOnMenu('Data', 'Processing');
  await leftBarPage.expectBreadcrumb('Data', 'Processing');
  await leftBarPage.clickOnMenu('Data', 'Data sharing');
  await leftBarPage.expectBreadcrumb('Data', 'Data sharing');

  // Checking Settings menu
  await leftBarPage.clickOnMenu('Settings', 'Parameters');
  await leftBarPage.expectBreadcrumb('Settings', 'Parameters');
  await leftBarPage.clickOnMenu('Settings', 'Security');
  await leftBarPage.expectBreadcrumb('Settings', 'Security');
  await leftBarPage.clickOnMenu('Settings', 'Customization');
  await leftBarPage.expectBreadcrumb('Settings', 'Customization');
  await leftBarPage.clickOnMenu('Settings', 'Taxonomies');
  await leftBarPage.expectBreadcrumb('Settings', 'Taxonomies');
  await leftBarPage.clickOnMenu('Settings', 'File indexing');
  await leftBarPage.expectBreadcrumb('Settings', 'File indexing');
  await leftBarPage.clickOnMenu('Settings', 'Filigran Experience');
  await leftBarPage.expectBreadcrumb('Settings', 'Filigran Experience');

  // Other
  await leftBarPage.clickOnMenu('Investigations');
  await leftBarPage.expectBreadcrumb('Investigations');
};

test('Check navigation on all pages', { tag: ['@navigation'] }, async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();

  // For faster debugging, each navigated can be commented.
  // so they should be all independent and start from the left menu.
  await navigateAllMenu(page);
});

test('Check navigation on Analyses menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateReports(page);
  await navigateGroupings(page);
  await navigateMalwareAnalyses(page);
  await navigateNotes(page);
  await navigateExternalReferences(page);
});

test('Check navigation on Cases menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateIncidentResponse(page);
  await navigateRfi(page);
  await navigateRft(page);
  await navigateTasks(page);
  await navigateFeedbacks(page);
});

test('Check navigation on Events menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateEventsIncident(page);
  await navigateSightings(page);
  await navigateObservedData(page);
});

test('Check navigation on Observations menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateObservables(page);
  await navigateArtifact(page);
  await navigateIndicators(page);
  await navigateInfrastructure(page);
});

test('Check navigation on Threats menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateIntrusionSet(page);
  await navigateCampaign(page);
  await navigateThreatActorGroup(page);
  await navigateThreatActorIndividual(page);
});

test('Check navigation on Arsenal menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateMalware(page);
  await navigateChannel(page);
  await navigateTool(page);
  await navigateVulnerability(page);
});

test('Check navigation on Techniques menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateAttackPattern(page);
  await navigateNarrative(page);
  await navigateCourseOfAction(page);
  await navigateDataComponent(page);
  await navigateDataSource(page);
});

test('Check navigation on Entities menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateSector(page);
  await navigateEvent(page);
  await navigateOrganization(page);
  await navigateSecurityPlatform(page);
  await navigateSystem(page);
  await navigateIndividual(page);
});

test('Check navigation on Locations menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateRegion(page);
  await navigateCountry(page);
  await navigateAdministrativeArea(page);
  await navigateCity(page);
  await navigatePosition(page);
});

test.skip('Check navigation on Data menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateDataEntities(page);
  await navigateDataRelationships(page);
  await navigateIngestion(page);
  await navigateDataImport(page);
  await navigateProcessing(page);
  await navigateDataSharing(page);
  await navigateDataManagement(page);
});

test('Check navigation on Trash menu', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateTrash(page);
});

// Separating settings menu in two to avoid timeout while testing as this part is too long

test('Check navigation on Settings menu part one', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateSettings(page);
  await navigateSecurity(page);
  await navigateCustomization(page);
  await navigateTaxonomies(page);
});

test('Check navigation on Settings menu part two', async ({ page }) => {
  await page.goto('/');
  const leftBarPage = new LeftBarPage(page);
  await leftBarPage.open();
  await navigateSettings(page);
  await navigateActivity(page);
  await navigateFileIndexing(page);
  await navigateExperience(page);
});
