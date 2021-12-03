import {UpdateOps} from "../utils";

export const addToInventoryQuery = (assetIri) => {
  return `
  INSERT {
    GRAPH ?g {
      ?inv <http://csrc.nist.gov/ns/oscal/common#assets> ${assetIri}
    } 
  } WHERE {
    GRAPH ?g {
      ?inv a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> 
    }
  }
  `
}

export const removeFromInventoryQuery = (id) => {
  return `
  DELETE {
    GRAPH ?g {
      ?inv <http://csrc.nist.gov/ns/oscal/common#assets> <http://scap.nist.gov/ns/asset-identification#Asset-${id}> .
    }
  } WHERE {
    GRAPH ?g {
      ?inv a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> .
    }
  }
  `
}

export const deleteQuery = (id) => {
  return `
  DELETE {
    GRAPH ?g{
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g{
      ?iri a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ?iri <http://darklight.ai/ns/common#id> "${id}". 
      ?iri ?p ?o
    }
  }
  `
}

export const updateAssetQuery = (iri, input, predicateMap) => {
  let deletePredicates = [], insertPredicates = [], replaceBindingPredicates = [];
  for(const {key, value, operation} of input) {
    if(!predicateMap.hasOwnProperty(key)) continue;
    for(const itr of value) {
      const predicate = predicateMap[key].binding(iri, itr);
      switch (operation) {
        case UpdateOps.ADD:
          insertPredicates.push(predicate);
          break;
        case UpdateOps.REPLACE:
          insertPredicates.push(predicate);
          replaceBindingPredicates.push(predicateMap[key].binding(iri))
          break;
        case UpdateOps.REMOVE:
          deletePredicates.push(predicate);
          break;
      }
    }
  }
  return `
DELETE {
  GRAPH ?g {
    ${deletePredicates.join('\n      ')}
    ${replaceBindingPredicates.join('\n      ')}
  }
} INSERT {
  GRAPH ?g {
    ${insertPredicates.join('\n      ')}
  }
} WHERE {
  GRAPH ?g {
    ${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> .
    ${replaceBindingPredicates.join('\n      ')}
  }
}
  `;
}