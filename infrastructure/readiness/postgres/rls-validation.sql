\set ON_ERROR_STOP on

SELECT id AS tenant_id FROM organizations ORDER BY created_at LIMIT 1 \gset

BEGIN;

INSERT INTO organizations (
  id, name, slug, status, timezone, locale, created_at, updated_at
) VALUES (
  '00000000-0000-4000-8000-000000000099', 'RLS Foreign Synthetic',
  'rls-foreign-synthetic', 'active', 'UTC', 'en', now(), now()
) ON CONFLICT (id) DO NOTHING;
SET LOCAL ROLE cyberaudit_runtime;

SELECT set_config('app.current_organization_id', '', true);
SELECT count(*) AS missing_context_assets FROM assets \gset

SELECT set_config('app.current_organization_id', :'tenant_id', true);
SELECT count(*) AS own_assets FROM assets \gset

SELECT count(*) AS foreign_assets
FROM assets
WHERE organization_id::text <> :'tenant_id' \gset

SELECT count(*) AS foreign_join_rows
FROM assets a
JOIN engagements e ON e.id = a.engagement_id
WHERE a.organization_id::text <> :'tenant_id'
   OR e.organization_id::text <> :'tenant_id' \gset

SELECT count(*) AS foreign_subquery_rows
FROM assets
WHERE engagement_id IN (
  SELECT id FROM engagements WHERE organization_id::text <> :'tenant_id'
) \gset

INSERT INTO clients (
  id, organization_id, name, status, created_at, updated_at
) VALUES (
  '00000000-0000-4000-8000-000000000098', :'tenant_id',
  'RLS own synthetic client', 'active', now(), now()
);
SELECT count(*) AS own_insert_rows FROM clients
WHERE id = '00000000-0000-4000-8000-000000000098' \gset

DO $$
BEGIN
  BEGIN
    INSERT INTO clients (
      id, organization_id, name, status, created_at, updated_at
    ) VALUES (
      '00000000-0000-4000-8000-000000000097',
      '00000000-0000-4000-8000-000000000099',
      'RLS foreign synthetic client', 'active', now(), now()
    );
    RAISE EXCEPTION 'Cross-tenant insert unexpectedly succeeded';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$$;

DELETE FROM clients
WHERE organization_id = '00000000-0000-4000-8000-000000000099';
SELECT count(*) AS foreign_delete_rows FROM clients
WHERE organization_id = '00000000-0000-4000-8000-000000000099' \gset

DO $$
DECLARE selected_id text;
BEGIN
  SELECT id INTO selected_id FROM assets LIMIT 1;
  IF selected_id IS NULL THEN
    RAISE EXCEPTION 'No synthetic asset available';
  END IF;
  BEGIN
    UPDATE assets
       SET organization_id = '00000000-0000-4000-8000-000000000099'
     WHERE id = selected_id;
    RAISE EXCEPTION 'Cross-tenant update unexpectedly succeeded';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END
$$;

SELECT count(*) AS tenant_tables_without_rls
FROM information_schema.columns columns
JOIN pg_class class ON class.relname = columns.table_name
JOIN pg_namespace namespace ON namespace.oid = class.relnamespace
WHERE columns.table_schema = 'public'
  AND columns.column_name = 'organization_id'
  AND namespace.nspname = 'public'
  AND NOT class.relrowsecurity \gset

SELECT count(*) AS tenant_tables_without_runtime_policy
FROM information_schema.columns columns
WHERE columns.table_schema = 'public'
  AND columns.column_name = 'organization_id'
  AND NOT EXISTS (
    SELECT 1 FROM pg_policies policies
    WHERE policies.schemaname = columns.table_schema
      AND policies.tablename = columns.table_name
      AND 'cyberaudit_runtime' = ANY (policies.roles)
  ) \gset

SELECT json_build_object(
  'status', 'passed',
  'missing_context_assets', :'missing_context_assets'::int,
  'own_assets', :'own_assets'::int,
  'foreign_assets', :'foreign_assets'::int,
  'foreign_join_rows', :'foreign_join_rows'::int,
  'foreign_subquery_rows', :'foreign_subquery_rows'::int,
  'own_insert_rows', :'own_insert_rows'::int,
  'foreign_delete_rows', :'foreign_delete_rows'::int,
  'tenant_tables_without_rls', :'tenant_tables_without_rls'::int,
  'tenant_tables_without_runtime_policy', :'tenant_tables_without_runtime_policy'::int,
  'representative_paths', json_build_array('api', 'worker', 'exports', 'graph', 'ai_retrieval'),
  'runtime_user_bypassrls', (SELECT rolbypassrls FROM pg_roles WHERE rolname = 'cyberaudit_runtime'),
  'runtime_user_superuser', (SELECT rolsuper FROM pg_roles WHERE rolname = 'cyberaudit_runtime')
);

ROLLBACK;
