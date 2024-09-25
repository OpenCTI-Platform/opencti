import { graphql } from 'react-relay';
import { useState } from 'react';
import { fetchQuery } from '../relay/environment';

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
const variable1 = {
  name: 'rapportName',
  type: 'attribute',
  value: 'name',
};

const templatesVariables = [variable1];

const containerDataQuery = graphql`
  query templatesVariablesUtilsContainerQuery(
    $id: String!
  ) {
    stixCoreObject(
      id: $id
    ) {
      id
      entity_type
      parent_types
      representative {
        main
        secondary
      }
      ... on Report {
        name
      }
    }
  }
`;

const useBuildOutcomeFromTemplate = ({
  containerId,
  template,
  max_content_markings,
}: {
  containerId: string,
  template: any,
  max_content_markings: string[],
}) => {
  const [resolvedVariables, setResolvedVariables] = useState<{ [p: string]: any }>({});

  const generateWidgetFromVariable = (variableName: string) => {
    const variable = templatesVariables.filter((v) => v.name === variableName)[0];
    if (variable.type === 'attribute') {
      // fetch container data
      fetchQuery(containerDataQuery, {
        id: containerId,
      })
        .toPromise()
        .then((data) => {
          console.log('data', data);
          console.log('result', data.stixCoreObject[variable.value]);
          console.log('value', variable.value);
          setResolvedVariables({ [variableName]: data.stixCoreObject[variable.value] });
        });
    } else {
      setResolvedVariables({ [variableName]: 'UNRESOLVED VARIABLE' });
    }
  };

  let result = template.content;
  template.used_variables.forEach((variableName) => {
    generateWidgetFromVariable(variableName);
    result = template.content.replace(`$${variableName}`, resolvedVariables[variableName]);
  });
  return result;
};

export default useBuildOutcomeFromTemplate;
