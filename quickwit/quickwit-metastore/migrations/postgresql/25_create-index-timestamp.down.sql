ALTER TABLE splits DROP COLUMN IF EXISTS index_time_range_start;
ALTER TABLE splits DROP COLUMN IF EXISTS index_time_range_end;

DROP INDEX IF EXISTS splits_index_time_range_start_idx;
DROP INDEX IF EXISTS splits_index_time_range_end_idx;
