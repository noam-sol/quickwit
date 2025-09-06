ALTER TABLE splits
ADD COLUMN IF NOT EXISTS index_time_range_start BIGINT,
ADD COLUMN IF NOT EXISTS index_time_range_end BIGINT;

CREATE INDEX IF NOT EXISTS splits_index_time_range_start_idx ON splits (index_time_range_start);
CREATE INDEX IF NOT EXISTS splits_index_time_range_end_idx ON splits (index_time_range_end);
