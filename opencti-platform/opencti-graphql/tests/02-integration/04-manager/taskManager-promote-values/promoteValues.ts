export const promoteIndicatorInput = {
  name: 'indicatorTestPromote',
  pattern: "[domain-name:value = 'indicatorTestPromote']",
  pattern_type: 'stix',
  x_opencti_main_observable_type: 'Domain-Name',
};

export const promoteObservableInput = {
  type: 'Domain-Name',
  DomainName: {
    value: 'observableTestPromote'
  },
};

export const promoteReportInput = {
  name: 'reportTestPromote',
  description: 'description',
};
