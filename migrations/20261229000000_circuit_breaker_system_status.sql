-- Create system_status table for circuit breaker functionality
-- Migration: 20261229000000_circuit_breaker_system_status.sql

-- Create system status table with single row constraint
CREATE TABLE IF NOT EXISTS system_status (
    id SERIAL PRIMARY KEY DEFAULT 1,
    status TEXT NOT NULL CHECK (status IN ('OPERATIONAL', 'PARTIAL_HALT', 'EMERGENCY_STOP')),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    triggered_at TIMESTAMP WITH TIME ZONE,
    last_anomaly JSONB,
    audit_required BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Ensure only one row exists
    CONSTRAINT single_status CHECK (id = 1)
);

-- Insert default operational status
INSERT INTO system_status (id, status)
VALUES (1, 'OPERATIONAL')
ON CONFLICT (id) DO NOTHING;

-- Create index for status queries
CREATE INDEX IF NOT EXISTS idx_system_status_updated_at 
ON system_status (updated_at DESC);

-- Add trigger to automatically update updated_at
CREATE OR REPLACE FUNCTION update_system_status_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_system_status_updated_at
    BEFORE UPDATE ON system_status
    FOR EACH ROW
    EXECUTE FUNCTION update_system_status_updated_at();

-- Add comments for documentation
COMMENT ON TABLE system_status IS 'Circuit breaker system status with automated anomaly detection';
COMMENT ON COLUMN system_status.status IS 'Current system status: OPERATIONAL, PARTIAL_HALT, or EMERGENCY_STOP';
COMMENT ON COLUMN system_status.triggered_at IS 'Timestamp when circuit breaker was last triggered';
COMMENT ON COLUMN system_status.last_anomaly IS 'JSON details of the last anomaly that triggered the circuit breaker';
COMMENT ON COLUMN system_status.audit_required IS 'Flag indicating if manual audit is required before system reset';

-- Create view for easy status monitoring
CREATE OR REPLACE VIEW system_status_monitor AS
SELECT 
    status,
    updated_at,
    triggered_at,
    audit_required,
    CASE 
        WHEN status = 'OPERATIONAL' THEN 'System is operating normally'
        WHEN status = 'PARTIAL_HALT' THEN 'Some operations are halted due to security concerns'
        WHEN status = 'EMERGENCY_STOP' THEN 'All operations are halted - emergency mode'
    END as status_description,
    EXTRACT(EPOCH FROM (NOW() - COALESCE(triggered_at, updated_at))) as seconds_since_trigger
FROM system_status
WHERE id = 1;

COMMENT ON VIEW system_status_monitor IS 'Real-time monitoring view for circuit breaker status';
