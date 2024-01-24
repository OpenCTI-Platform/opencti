interface Work {
    _index: string
    id: string
    sort: number[]
    internal_id: string
    timestamp: string
    updated_at: string
    name: string
    entity_type: string
    event_type: string
    event_source_id: string
    user_id: string
    connector_id: string
    status: string
    import_expected_number: number
    received_time: string | null
    processed_time: string | null
    completed_time: string | null
    completed_number: string
    messages: string[]
    errors: string[]
}