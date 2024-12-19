import type { FintelTemplateAddInput } from '../../generated/graphql';
import { widgetAttackPatterns, widgetContainerObservables, widgetIncidentIOC, widgetIncidentResponseMultiAttributes, widgetIncidentTasksActions } from './__fintelTemplateWidgets';

const content = `
<div>
  <h2>Incident Response Report: $containerName</h2>
  
  <h3>1. Details</h3>
  <table>
    <tbody>
      <tr>
        <td><strong>Creation date</strong></td>
        <td>$containerCreationDate</td>
      </tr>
      <tr>
        <td><strong>Last modified date</strong></td>
        <td>$containerModificationDate</td>
      </tr>
      <tr>
        <td><strong>Priority</strong></td>
        <td>$incidentPriority</td>
      </tr>
      <tr>
        <td><strong>Severity</strong></td>
        <td>$incidentSeverity</td>
      </tr>
      <tr>
        <td><strong>Incident response type</strong></td>
        <td>$types</td>
      </tr>
      <tr>
        <td><strong>Labels</strong></td>
        <td>$containerLabels</td>
      </tr>
      <tr>
        <td><strong>Markings</strong></td>
        <td>$containerMarkings</td>
      </tr>
    </tbody>
  </table>
  
  <div class="page-break" style="page-break-after:always;">
    <span style="display:none;">&nbsp;</span>
  </div>
  
  <h3>2. Executive Summary</h3>
  <div>$containerDescription</div>
  
  <h3>3. Incident Analysis</h3>
  <blockquote>
    <p>To be completed by the analyst. This section should clearly describe:</p>
    <ul>
      <li><strong>Root cause</strong>: Highlight the underlying reason(s) for the incident.</li>
      <li><strong>Attack Vector</strong>: Describe how the attack was carried out, including the methods and tools used.</li>
      <li><strong>Impact</strong>: Assess the scope, systems affected and overall consequences of the incident.</li>
      <li><strong>Detection and response</strong>: Examine how the incident was detected and the effectiveness of the response.</li>
    </ul>
  </blockquote>
  
  <div class="page-break" style="page-break-after:always;">
    <span style="display:none;">&nbsp;</span>
  </div>
  
  <h3>4. Incident Response Tasks/Actions</h3>
  <div>$incidentTasksAndActions</div>
  
  <h3>5. Recommendations</h3>
  <blockquote>
    <p>To be completed by the analyst. The recommendations section details the actions necessary to prevent similar incidents in the future.</p>
  </blockquote>
  
  <h3>6. Indicators of Compromise (IoCs)</h3>
  <div>$incidentIOC</div>
  
  <div class="page-break" style="page-break-after:always;">
    <span style="display:none;">&nbsp;</span>
  </div>
  
  <h3>7. Observables</h3>
  <div>$containerObservables</div>
  
  <div class="page-break" style="page-break-after:always;">
    <span style="display:none;">&nbsp;</span>
  </div>
  
  <h3>8. Tactics, Techniques, and Procedures (TTPs)</h3>
  <div>$attackPatterns</div>
  
  <div class="page-break" style="page-break-after:always;">
    <span style="display:none;">&nbsp;</span>
  </div>
  
  <h3>9. References</h3>
  <div>$containerReferences</div>
</div>
`;

export const fintelTemplateIncidentResponse: FintelTemplateAddInput = {
  name: 'Incident Response Report',
  content,
  start_date: '1970-01-01T00:00:00Z',
  settings_types: ['Case-Incident'],
  fintel_template_widgets: [
    widgetContainerObservables,
    widgetIncidentIOC,
    widgetIncidentTasksActions,
    widgetAttackPatterns,
    widgetIncidentResponseMultiAttributes,
  ],
};
