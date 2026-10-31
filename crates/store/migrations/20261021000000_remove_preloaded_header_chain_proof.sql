-- Remove only the preloaded proof record from migration 20251215024440.
DELETE FROM long_running_task_proof
WHERE chain_name = 'header-chain'
  AND block_start = 0
  AND block_end = 116000
  AND path_to_proof = '../circuits/data/header-chain/0-116000.bin'
  AND cycles = 3147770424
  AND proof_state = 2
  AND total_time_to_proof = 637403
  AND proving_time = 637403
  AND zkm_version = 'v1.2.3'
  AND extra = ''
  AND proof_size = 0
  AND public_value_hex IS NULL
  AND created_at = 0
  AND updated_at = 0;
