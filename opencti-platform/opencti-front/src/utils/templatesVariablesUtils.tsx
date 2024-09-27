import { graphql } from 'react-relay';
import React from 'react';
import StixCoreObjectAttributeWidget from '@components/common/stix_core_objects/StixCoreObjectAttributeWidget';
import { renderToString } from 'react-dom/server';
import { IntlProvider } from 'react-intl';
import { addFilter } from './filters/filtersUtils';

// hardcoded templates //
export const template1 = { // only text
  name: 'template1',
  content: '<body>\n'
    + '<h1> Voici le titre principal </h1>\n'
    + '<p> Et voilà le texte de la page</p>\n'
    + '<h2> On crée les autres titres de la même manière </h2>\n'
    + '<h3> On peut créer jusqu\'à six niveaux de titres </h3>\n'
    + '<h4> Titre de niveau 4 </h4>\n'
    + '<h5> Titre de niveau 5 </h5>\n'
    + '<h6> Titre de niveau 6 </h6>\n'
    + '<p> Chaque titre peut contenir du texte, comme ici </p> \n'
    + '</body> \n'
    + '</html>',
  used_variables: [],
};

export const template2 = {
  name: 'template2',
  content: '<body>\n'
    + '<h1> Titre principal </h1>\n'
    + '<p> nom du rapport: $rapportName</p>\n'
    + '</body> \n'
    + '</html>',
  used_variables: ['rapportName'],
};

// hardcoded variables //
const widget1 = {
  type: 'attribute',
  perspective: 'entities',
  parameters: {
    title: 'Report name (widget title)',
  },
  dataSelection: [
    {
      attribute: 'representative.main',
    },
  ],
};
const variable1 = {
  name: 'rapportName',
  widget: widget1,
};
const variable2 = {
  name: 'rapportPublished',
  type: 'attribute',
  value: 'published',
};

const templatesVariables = [variable1, variable2];

const containerDataQuery = graphql`
  query templatesVariablesUtilsContainerQuery(
    $id: String!
  ) {
    stixCoreObject(
      id: $id
    ) {
      id
      entity_type
      representative {
        main
        secondary
      }
      objectMarking {
          id
          standard_id
          entity_type
          definition_type
          definition
          created
          modified
          x_opencti_order
          x_opencti_color
      }
      objectLabel {
          id
          value
          color
      }
      ... on Report {
        name
        description
        report_types
        published
      }
    }
  }
`;

const buildOutcomeFromTemplate = ({
  containerId,
  template,
  max_content_markings,
}: {
  containerId: string,
  template: any,
  max_content_markings: string[],
}) => {
  const generateWidgetFromVariable = (variableName: string) => {
    const variable = templatesVariables.filter((v) => v.name === variableName)[0];
    const { widget } = variable;
    if (widget.type === 'attribute') {
      const dataSelectionForContainerId = widget.dataSelection.map((d) => ({
        ...d,
        filters: addFilter(d.filters, 'id', containerId),
      }));
      return (
        <StixCoreObjectAttributeWidget
          dataSelection={dataSelectionForContainerId}
          parameters={widget.parameters}
          variant="inLine"
        />
      );
    }
    return (<h1>
      UNRESOLVED VARIABLE
    </h1>);
  };

  let result = template.content;
  template.used_variables.forEach((variableName) => {
    const resolvedVariable = generateWidgetFromVariable(variableName);
    const htmlVariable = renderToString(<IntlProvider locale={'en'}>{resolvedVariable}</IntlProvider>);
    result = template.content.replace(`$${variableName}`, htmlVariable);
  });
  return result;
};

export default buildOutcomeFromTemplate;
