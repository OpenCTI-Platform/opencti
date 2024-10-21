import type { Template } from './template';

const content = `
<body>
  <h1>Incident Response Report: $containerName</h1>
  
  <h2>1. Details</h2>
  <table>
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
      <td>$incidentType</td>
    </tr>
    <tr>
      <td><strong>Labels</strong></td>
      <td>$containerLabels</td>
    </tr>
    <tr>
      <td><strong>Markings</strong></td>
      <td>$containerMarkings</td>
    </tr>
  </table>
  
  <h2>2. Executive Summary</h2>
  <p>$containerDescription</p>
  
  <h2>3. Incident Analysis</h2>
  <blockquote>
    <p>To be completed by the analyst. This section should clearly describe:</p>
    <ul>
      <li><strong>Root cause</strong>: Highlight the underlying reason(s) for the incident.</li>
      <li><strong>Attack Vector</strong>: Describe how the attack was carried out, including the methods and tools used.</li>
      <li><strong>Impact</strong>: Assess the scope, systems affected and overall consequences of the incident.</li>
      <li><strong>Detection and response</strong>: Examine how the incident was detected and the effectiveness of the response.</li>
    </ul>
  </blockquote>
  
  <h2>4. Incident Response Tasks/Actions</h2>
  <div>$incidentTasksActions</div>
  
  <h2>5. Recommendations</h2>
  <blockquote>
    <p>To be completed by the analyst. The recommendations section details the actions necessary to prevent similar incidents in the future.</p>
  </blockquote>
  
  <h2>6. Indicators of Compromise (IoCs)</h2>
  <div>$incidentIOC</div>
  
  <h2>7. Observables</h2>
  <div>$containerObservables</div>
  
  <h2>8. Tactics, Techniques, and Procedures (TTPs)</h2>
  <div>$incidentTTP</div>
  
  <h2>9. References</h2>
  <div>$containerReferences</div>
</body>
`;

const templateIncidentCase: Template = {
  name: 'Incident Response Report',
  content,
  used_widgets: [
    'containerName',
    'containerCreationDate',
    'containerDescription',
    'containerLabels',
    'containerMarkings',
    'containerModificationDate',
    'containerObservables',
    'containerReferences',
    'incidentIOC',
    'incidentPriority',
    'incidentSeverity',
    'incidentTasksActions',
    'incidentTTP',
    'incidentType',
  ],
};

export default templateIncidentCase;
