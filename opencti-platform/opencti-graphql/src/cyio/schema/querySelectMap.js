
export default function querySelectMap(info) {
  const selectSet = buildNodeSet(info.fieldNodes);
  const fragmentSet = extractFragments(info.fragments);
  for(const nodeName in selectSet){
    expandFragments(selectSet[nodeName], fragmentSet);
  }
  return {
    ...selectSet,
    getNode: function (name) {
      for(const nodeName in this){
        const node = this[nodeName];
        if(nodeName === name) return node.select;
        const found = this._getNode(node.children, name);
        if(found) return found.select;
      }
      return null;
    },
    _getNode: function (children, name) {
      if(name in children) {
        return children[name];
      }
      for(const childName in children) {
        const child = children[childName];
        if(child.children) {
          const node = this._getNode(child.children, name);
          if(node) return node;
        }
      }
      return null;
    }
  }
}

const expandFragments = (node, fragments) => {
  if(node.select){
    for(const fragName in fragments) {
      if(node.select.includes(fragName)){
        node.select = node.select.filter(i => i !== fragName)
        const fragment = fragments[fragName]
        node.select = node.select.concat(fragment.select.filter((i) => node.select.indexOf(i) < 0))
        node.children = { ...node.children, ...fragment.children }
      }
    }
  }
  if(node.children){
    for(const nodeName in node.children){
      const child = node.children[nodeName]
      expandFragments(child, fragments)
    }
  }
}

const buildNodeSet = (nodes) => {
  let rootMap = {};
  for(const rootNode of nodes) {
    const { select, children } = buildSelection(rootNode);
    const nodeMap = {};
    if(select) nodeMap.select = select;
    if(children) nodeMap.children = children;
    rootMap[rootNode.name.value] = nodeMap;
  }
  return rootMap;
}

const buildSelection = (node) => {
  const map = {};
  const select = [];
  const children = {};
  for(const child of node.selectionSet?.selections || []){
    if(child.selectionSet){ // Indicates an object node
      const { select: childSelect, children: childChildren } = buildSelection(child);
      const childMap = {};
      if(childSelect) childMap.select = childSelect;
      if(childChildren) childMap.children = childChildren;
      children[child.name.value] = childMap;
    }
    select.push(child.name.value);
  }
  if(select.length > 0) map.select = select
  if(Object.getOwnPropertyNames(children).length > 0) map.children = children;
  return map;
}

const extractFragments = (fragments) => {
  if(!fragments) return {};
  const fragmentNodes = []
  for(const fragmentName in fragments) {
    fragmentNodes.push(fragments[fragmentName])
  }
  return buildNodeSet(fragmentNodes)
}
