import { Page } from '@playwright/test';
import StixCoreObjectDataTab from 'tests_e2e/model/StixCoreObjectDataTab.pageModel';
import FeedbackDetailsPage from 'tests_e2e/model/feedbackDetails.pageModel';
import ObservedDataPage from 'tests_e2e/model/observedData.pageModel';
import CaseRftPage from 'tests_e2e/model/caseRft.pageModel';
import CaseRftDetailsPage from 'tests_e2e/model/caseRftDetails.pageModel';
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
  await expect(page.getByRole('link', { name: 'Malware Spelevo EK admin covid-19' })).toBeVisible();

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
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await incidentResponseDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Entity types')).toBeVisible();
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
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await caseRfiDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Entity types')).toBeVisible();
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
  await expect(page.getByText('Description', { exact: true })).toBeVisible();
  await expect(page.getByText('Mappable content')).toBeVisible();

  // -- Entities
  await caseRftDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByText('Entity types')).toBeVisible();
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

  // await navigateAllMenu(page);
  await navigateReports(page);
  await navigateGroupings(page);
  await navigateMalwareAnalyses(page);
  await navigateNotes(page);
  await navigateExternalReferences(page);
  await navigateIncidentResponse(page);
  await navigateRfi(page);
  await navigateRft(page);
  await navigateTasks(page);
  await navigateFeedbacks(page);
  await navigateEventsIncident(page);
  await navigateSightings(page);
  await navigateObservedData(page);
  await navigateObservables(page);
  await navigateArtifact(page);
  await navigateIndicators(page);
  await navigateInfrastructure(page);
});
