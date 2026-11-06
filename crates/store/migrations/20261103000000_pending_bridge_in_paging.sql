-- Keep bounded pending-request pages efficient as the history table grows.
CREATE INDEX idx_goat_tx_record_pending_page
    ON goat_tx_record (tx_type, processing_status, height, instance_id, graph_id);
