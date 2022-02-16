const cyioGlobalTypeResolvers = {
  Mutation: {
    addReference: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // if the types are not supplied, just return false - this will be removed when the field are required
      if (input.from_type === undefined || input.to_type === undefined ) return false;

      let fromType;
      switch( input.from_type) {
        case 'ComputingDeviceAsset':
        case 'computing-device':
          fromType = 'ComputingDevice';
          break;
        case 'NetworkAsset':
        case 'network':
          fromType = 'Network';
          break;
        case 'SoftwareAsset':
        case 'software':
          fromType = 'Software';
          break;
        default:
          fromType = input.from_type;
      }

      let predicate, toIri;
      const fromIri = `<http://scap.nist.gov/ns/asset-identification#${fromType}-${input.from_id}>`;
      switch(input.field_name) {
        case 'labels': 
          predicate = `<http://darklight.ai/ns/common#labels>`;
          toIri = `<http://darklight.ai/ns/common#Label-${input.to_id}>`;
          break;
        case 'external_references':
          predicate = `<http://darklight.ai/ns/common#external_references>`;
          toIri = `<http://darklight.ai/ns/common#ExternalReference-${input.to_id}>`;
          break;
        case 'notes':
          predicate = `<http://darklight.ai/ns/common#notes>`;
          toIri = `<http://darklight.ai/ns/common#Note-${input.to_id}>`;
          break;
        default:
          throw new Error(`Unsupported field '${input.field_name}'`)
      }
      
      const query = `
      INSERT DATA {
        GRAPH ${fromIri} {
          ${fromIri} ${predicate} ${toIri} .
        }
      }
      `;
      let response;
      try {
       response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create reference"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return false;
      return true
    },
    removeReference: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // if the types are not supplied, just return false - this will be removed when the field are required
      if (input.from_type === undefined || input.to_type === undefined ) return false;

      let fromType;
      switch( input.from_type) {
        case 'ComputingDeviceAsset':
        case 'computing-device':
          fromType = 'ComputingDevice';
          break;
        case 'NetworkAsset':
        case 'network':
          fromType = 'Network';
          break;
        case 'SoftwareAsset':
        case 'software':
          fromType = 'Software';
          break;
        default:
          fromType = input.from_type;
      }

      let predicate, toIri;
      const fromIri = `<http://scap.nist.gov/ns/asset-identification#${fromType}-${input.from_id}>`;
      switch(input.field_name) {
        case 'labels': 
          predicate = `<http://darklight.ai/ns/common#labels>`;
          toIri = `<http://darklight.ai/ns/common#Label-${input.to_id}>`;
          break;
        case 'external_references':
          predicate = `<http://darklight.ai/ns/common#external_references>`;
          toIri = `<http://darklight.ai/ns/common#ExternalReference-${input.to_id}>`;
          break;
        case 'notes':
          predicate = `<http://darklight.ai/ns/common#notes>`;
          toIri = `<http://darklight.ai/ns/common#Note-${input.to_id}>`;
          break;
        default:
          throw new Error(`Unsupported field '${input.field_name}'`)
      }

      const query = `
      DELETE DATA {
        GRAPH ${fromIri} {
          ${fromIri} ${predicate} ${toIri} .
        }
      }
      `;
      let response;
      try {
       response = await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Remove reference"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return false;
      return true
    },
  },
  // Map enum GraphQL values to data model required values
  OperationalStatus: {
    under_development : 'under-development',
    under_major_modification: 'under-major-modifications',
  },
  CyioLocationType: {
    geo_location: 'geo-location',
    civic_address: 'civic-address',
  },
  RegionName: {
    africa: 'africa',
    eastern_africa: 'eastern-africa',
    middle_africa: 'middle-africa',
    northern_africa: 'northern-africa',
    southern_africa: 'southern-africa',
    western_africa: 'western-africa',
    americas: 'americas',
    caribbean: 'caribbean',
    central_america: 'central-america',
    latin_america_caribbean: 'latin-america-caribbean',
    northern_america: 'northern-america',
    south_america: 'south-america',
    asia: 'asia',
    central_asia: 'central-asia',
    eastern_asia: 'eastern-asia',
    southern_asia: 'southern-asia',
    south_eastern_asia: 'south-eastern-asia',
    western_asia: 'western-asia',
    europe: 'europe',
    eastern_europe: 'eastern-europe',
    northern_europe: 'northern-europe',
    southern_europe: 'southern-europe',
    western_europe: 'western-europe',
    oceania: 'oceania',
    antarctica: 'antarctica',
    australia_new_zealand: 'australia-new-zealand',
    melanesia: 'melanesia',
    micronesia: 'micronesia',
    polynesia: 'polynesia',
  },
}

export default cyioGlobalTypeResolvers;