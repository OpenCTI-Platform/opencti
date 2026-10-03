import { memo } from 'react';
import { Handle, Position, type NodeProps } from 'reactflow';

const TargetGroupNode = memo(({ data, selected }: NodeProps) => {
    const onJump = (e: React.MouseEvent, label: string) => {
        e.stopPropagation();
        const event = new CustomEvent('jumpToNode', { detail: { nodeId: label } });
        window.dispatchEvent(event);
    };

    return (
        <div className={`react-flow__node-custom ${selected ? 'selected' : ''}`} style={{
            minWidth: '200px',
            borderStyle: 'dashed',
            borderColor: '#94a3b8',
            backgroundColor: 'rgba(30, 41, 59, 0.5)'
        }}>
            <Handle type="target" position={Position.Top} style={{ background: '#555' }} />

            <div className="node-header duplicate" style={{ justifyContent: 'center' }}>
                <span style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '1px' }}>
                    Possible Targets ({data.items?.length || 0})
                </span>
            </div>

            <div className="attributes-list" style={{ padding: '8px' }}>
                {data.items && data.items.map((item: { label: string; isRelationship: boolean }) => (
                    <div key={item.label}
                        onClick={(e) => !item.isRelationship && onJump(e, item.label)}
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '4px 8px',
                            background: item.isRelationship ? 'rgba(236, 72, 153, 0.1)' : 'rgba(255, 255, 255, 0.05)',
                            border: item.isRelationship ? '1px solid rgba(236, 72, 153, 0.3)' : '1px solid transparent',
                            marginBottom: '4px',
                            borderRadius: '4px',
                            cursor: item.isRelationship ? 'default' : 'pointer',
                            fontSize: '0.8rem',
                            color: item.isRelationship ? '#fbcfe8' : 'inherit'
                        }}
                        className="group-item"
                    >
                        <span style={{ fontWeight: item.isRelationship ? 600 : 400 }}>
                            {item.label}
                        </span>
                        {!item.isRelationship && (
                            <span style={{ fontSize: '0.8em', color: '#94a3b8' }}>↗</span>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
});

export default TargetGroupNode;
