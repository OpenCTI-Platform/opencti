import { memo } from 'react';
import { Handle, Position, type NodeProps } from 'reactflow';

const CustomNode = memo(({ id, data, selected }: NodeProps) => {
    // const [expanded, setExpanded] = useState(false); // Controlled by App now
    // Actually, App controls it via data.forceExpanded. But do we allow local toggle? 
    // Yes, we toggle by dispatching event.
    // So we don't strictly need local state if we trust App to update data.forceExpanded.
    // But `CustomNode` uses `expanded` variable depending on `data.forceExpanded`.
    // Let's remove local state and derive from prop.
    const expanded = data.forceExpanded || false;

    // const { fitView } = useReactFlow();

    const onJump = (e: React.MouseEvent) => {
        e.stopPropagation();
        const event = new CustomEvent('jumpToNode', { detail: { nodeId: id } });
        window.dispatchEvent(event);
    };

    const toggleExpand = (e: React.MouseEvent) => {
        e.stopPropagation();
        const event = new CustomEvent('toggleNode', { detail: { nodeId: id, isExpanded: expanded } });
        window.dispatchEvent(event);
    };

    return (
        <div className={`react-flow__node-custom ${selected ? 'selected' : ''} ${data.isDuplicate ? 'is-duplicate' : ''} ${data.simplified ? 'simplified' : ''}`}>
            {/* Allow incoming edges (Target) at Top AND Bottom to support both standard flow and upstream inheritance */}
            <Handle type="target" position={Position.Top} id="t-top" style={{ background: '#555' }} />
            <Handle type="target" position={Position.Bottom} id="t-bottom" style={{ background: '#555' }} />

            {/* Allow outgoing edges (Source) at Top AND Bottom */}
            <Handle type="source" position={Position.Top} id="s-top" style={{ background: '#555' }} />
            <Handle type="source" position={Position.Bottom} id="s-bottom" style={{ background: '#555' }} />

            <div className={`node-header ${data.isRelationship ? (data.isRefAttribute ? 'ref-attribute' : 'relationship') : (data.isDuplicate ? 'duplicate' : 'entity')}`}>
                <div style={{ display: 'flex', alignItems: 'center', maxWidth: '100%', overflow: 'hidden' }}>
                    {data.isDuplicate && (
                        <button className="jump-btn" onClick={onJump} title="Go to Definition">
                            Jump
                        </button>
                    )}
                    <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }} title={data.label}>
                        {data.label}
                    </span>
                    {data.isRelationship && data.stixType && !data.isRefAttribute && (
                        <div style={{ marginLeft: '8px', display: 'flex', gap: '4px', flexShrink: 0 }}>
                            {data.stixType === 'builtin' && <div className="stix-badge">STIX</div>}
                            {data.stixType === 'extended' && <div className="non-stix-badge">EXT</div>}
                            {data.stixType === 'new' && <div className="non-stix-badge" style={{ color: '#60a5fa', background: 'rgba(96, 165, 250, 0.1)' }}>NEW</div>}
                        </div>
                    )}
                    {data.isRefAttribute && (
                        <div style={{ marginLeft: '8px', display: 'flex', gap: '4px', flexShrink: 0 }}>
                            <div className="non-stix-badge">EXT</div>
                        </div>
                    )}
                </div>
                {!data.isDuplicate && !data.simplified && (
                    <button
                        className="toggle-btn"
                        onClick={toggleExpand}
                    >
                        {expanded ? '▼' : '▶'}
                    </button>
                )}
            </div>

            {expanded && !data.simplified && (
                <div className="attributes-list">
                    {data.attributes && data.attributes.length > 0 ? (
                        data.attributes.map((attr: { name: string; type: string; isStix: boolean }) => (
                            <div key={attr.name} className="attribute-item">
                                <div className="attribute-name">{attr.name}</div>
                                <div className="attribute-meta">
                                    <div className="type-badge">{attr.type}</div>
                                    {attr.isStix ? (
                                        <div className="stix-badge" title="STIX 2.1 Compliant">STIX</div>
                                    ) : (
                                        <div className="non-stix-badge" title="OpenCTI Extension">EXT</div>
                                    )}
                                </div>
                            </div>
                        ))
                    ) : (
                        <div className="attribute-item" style={{ color: '#666', fontStyle: 'italic' }}>No attributes</div>
                    )}
                </div>
            )}
        </div>
    );
});

export default CustomNode;
