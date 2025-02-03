import {
  widgetAllEntitiesAndObservables,
  widgetAttackPatterns,
  widgetGroupingMultiAttributes,
  widgetIncidentResponseMultiAttributes,
  widgetIndicators,
  widgetReportMultiAttributes,
  widgetRFIMultiAttributes,
  widgetRFTMultiAttributes,
  widgetThreats,
  widgetVictims
} from './__fintelTemplateWidgets';
import type { FintelTemplateAddInput } from '../../generated/graphql';

const executiveSummaryContent = (containerType: string) => {
  let typeLabel = 'Types';
  let typeWidget = '$types';
  if (containerType === 'Grouping') {
    typeLabel = 'Context';
    typeWidget = '$context';
  } else if (containerType === 'Report') {
    typeWidget = '$reportTypes';
  } else if (containerType === 'Case-Rfi') {
    typeWidget = '$informationTypes';
  } else if (containerType === 'Case-Rft') {
    typeWidget = '$takedownTypes';
  }
  const reliabilityForReport = containerType === 'Report'
    ? `<tr>
      <td><strong>Self reliability</strong></td>
  <td>$reliabilitySelf</td>
  </tr>`
    : '';
  return `
    <div>
      <h2>Executive report</h2>
      
      <h3>1. Details</h3>
      <table>
        <tbody>
          <tr>
            <td><strong>Creation date</strong></td>
            <td>$creationDate</td>
          </tr>
          <tr>
            <td><strong>Last update</strong></td>
            <td>$modificationDate</td>
          </tr>
          <tr>
            <td><strong>${typeLabel}</strong></td>
            <td>${typeWidget}</td>
          </tr>
          ${reliabilityForReport}
          <tr>
            <td><strong>Author reliability</strong></td>
            <td>$reliabilityOfAuthor</td>
          </tr>
          <tr>
            <td><strong>Confidence level</strong></td>
            <td>$confidenceLevel</td>
          </tr>
          <tr>
            <td><strong>Labels</strong></td>
            <td>$labels</td>
          </tr>
          <tr>
            <td><strong>Markings</strong></td>
            <td>$markings</td>
          </tr>
          <tr>
            <td><strong>Author</strong></td>
            <td>$author</td>
          </tr>
        </tbody>
      </table>
      
      <h3>2. Executive Summary</h3>
      <div>$description</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>3. Key points</h3>
      <blockquote>
        <p>To be completed by the analyst. The key points section details:</p>
        <ul>
          <li>The timeline of the incident/risk </li>
          <li>The attribution of the incident/risk: pick the main threats from this list.</li>
          <li>The main victims of the incident/risk: pick the main form the list.</li>
        </ul>
      </blockquote>
      <div>$threats</div>
      <div>$victims</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>4. Assessment</h3>
      <blockquote>
        <p>To be completed by the analyst. The assessment section details:</p>
        <ul>
          <li>The impact of the incident/risk </li>
          <li>The attack pattern used to deliver/create the risk/incident: use the</li>
          <li>The security posture of the company against that risk/incident in regards of the attack patterns used</li>
        </ul>
      </blockquote>
      <div>$attackPatterns</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>5. All entities & observables</h3>
      <blockquote>
        <p>This section is meant to help you draft your final outcome. It gathers all entities & observables in your container.</p>
      </blockquote>
      <div>$allEntitiesAndObservables</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>6. IoCs</h3>
      <blockquote>
        <p>This section is meant to help you draft your final outcome. It gathers all indicators in your container.</p>
      </blockquote>
      <div>$indicators</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>7. Data sources</h3>
      <div>$externalReferencesURL</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
    
    </div>
  `;
};

const getMultiAttributesWidget = (containerType: string) => {
  switch (containerType) {
    case 'Report':
      return widgetReportMultiAttributes;
    case 'Grouping':
      return widgetGroupingMultiAttributes;
    case 'Case-Incident':
      return widgetIncidentResponseMultiAttributes;
    case 'Case-Rfi':
      return widgetRFIMultiAttributes;
    case 'Case-Rft':
      return widgetRFTMultiAttributes;
    default:
      return widgetReportMultiAttributes;
  }
};

export const generateFintelTemplateExecutiveSummary = (containerType: string): FintelTemplateAddInput => {
  const multiAttributesWidget = getMultiAttributesWidget(containerType);
  return {
    name: 'Executive Summary',
    template_content: executiveSummaryContent(containerType),
    settings_types: [containerType],
    start_date: '1970-01-01T00:00:00Z',
    fintel_template_widgets: [
      multiAttributesWidget,
      widgetIndicators,
      widgetAttackPatterns,
      widgetThreats,
      widgetVictims,
      widgetAllEntitiesAndObservables,
    ],
  };
};
