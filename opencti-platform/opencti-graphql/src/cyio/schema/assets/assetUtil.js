
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
