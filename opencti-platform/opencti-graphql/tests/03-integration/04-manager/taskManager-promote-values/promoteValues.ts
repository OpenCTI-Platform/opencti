export const promoteIndicatorInput = {
  name: 'indicatorTestPromote',
  pattern: "[domain-name:value = 'indicatorTestPromote.com']",
  pattern_type: 'stix',
  x_opencti_main_observable_type: 'Domain-Name',
};

export const promoteObservableInput = {
  type: 'Domain-Name',
  DomainName: {
    value: 'observableTestPromote.com'
  },
};

export const promoteReportInput = {
  name: 'reportTestPromote',
  published: '2022-10-06T22:00:00.000Z',
  description: 'description',
};
