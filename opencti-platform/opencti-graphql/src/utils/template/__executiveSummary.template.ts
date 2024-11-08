const executiveSummaryContent = (containerType: string) => {
  let typeLabel = 'Types';
  let typeWidget = '$types';
  if (containerType === 'Grouping') {
    typeLabel = 'Context';
    typeWidget = '$context';
  }
  const reliabilityForReport = containerType === 'Report'
    ? `<tr>
      <td><strong>Self reliability</strong></td>
  <td>$reportReliability</td>
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
            <td>$containerCreationDate</td>
          </tr>
          <tr>
            <td><strong>Last update</strong></td>
            <td>$containerModificationDate</td>
          </tr>
          <tr>
            <td><strong>${typeLabel}</strong></td>
            <td>${typeWidget}</td>
          </tr>
          ${reliabilityForReport}
          <tr>
            <td><strong>Author reliability</strong></td>
            <td>$containerReliabilityOfAuthor</td>
          </tr>
          <tr>
            <td><strong>Confidence level</strong></td>
            <td>$containerConfidenceLevel</td>
          </tr>
          <tr>
            <td><strong>Labels</strong></td>
            <td>$containerLabels</td>
          </tr>
          <tr>
            <td><strong>Markings</strong></td>
            <td>$containerMarkings</td>
          </tr>
          <tr>
            <td><strong>Author</strong></td>
            <td>$containerAuthor</td>
          </tr>
        </tbody>
      </table>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>2. Executive Summary</h3>
      <p>$containerDescription</p>
      
      <h3>3. Key points</h3>
      <blockquote>
        <p>To be completed by the analyst. The key points section details:</p>
        <ul>
          <li>The timeline of the incident/risk </li>
          <li>The attribution of the incident/risk: pick the main threats from this list. <strong>REMOVE THE TABLE ONCE DONE</strong></li>
          <div>$threatsId</div>
          <li>The main victims of the incident/risk: pick the main form the list.  <strong>REMOVE THE TABLE ONCE DONE</strong></li>
          <div>$victimsId</div>
        </ul>
      </blockquote>
      
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
      <div>$attackPatternsId</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>5. All entities & observables</h3>
      <blockquote>
        <p>This section is meant to help you draft your final outcome. It gathers all entities & observables in your container. <strong>REMOVE THE TABLE ONCE DONE</strong></p>
      </blockquote>
      <div>$allEntitiesAndObservablesId</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>6. IoCs</h3>
      <blockquote>
        <p>This section is meant to help you draft your final outcome. It gathers all indicators in your container. <strong>REMOVE THE TABLE ONCE DONE</strong></p>
      </blockquote>
      <div>$indicatorsId</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
      
      <h3>7. Data sources</h3>
      <div>$containerReferences</div>
      
      <div class="page-break" style="page-break-after:always;">
        <span style="display:none;">&nbsp;</span>
      </div>
    
    </div>
  `;
};

const getMultiAttributesWidget = (containerType: string) => {
  switch (containerType) {
    case 'Report':
      return 'widgetReportMultiAttributesId';
    case 'Grouping':
      return 'widgetGroupingMultiAttributesId';
    case 'Case-Incident':
      return 'widgetIncidentResponseMultiAttributesId';
    case 'Case-Rfi':
      return 'widgetRFIMultiAttributesId';
    case 'Case-Rft':
      return 'widgetRFTMultiAttributesId';
    default:
      return 'widgetReportMultiAttributesId';
  }
};

export const generateTemplateExecutiveSummary = (containerType: string) => {
  const multiAttributesWidget = getMultiAttributesWidget(containerType);
  return {
    name: 'Executive Summary',
    id: 'executiveSummary-id',
    content: executiveSummaryContent(containerType),
    template_widgets_ids: [
      multiAttributesWidget,
      'indicatorsId',
      'attackPatternsId',
      'threatsId',
      'victimsId',
      'allEntitiesAndObservablesId',
    ],
  };
};
