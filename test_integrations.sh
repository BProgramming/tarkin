#!/bin/bash
set -e

CONTAINER_NAME="tarkin_test_db"
DB_NAME="tarkin_test"
DB_USER="tarkin"
DB_PASS="tarkin"
DB_PORT="54320"

trap "echo 'Tearing down test database...' && docker rm -f $CONTAINER_NAME" EXIT

IMAGE_NAME="tarkin_test_postgres"

echo "Building test image..."
docker build -f Dockerfile.test -t "$IMAGE_NAME" . --quiet

echo "Starting test database..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -e POSTGRES_DB="$DB_NAME" \
  -e POSTGRES_USER="$DB_USER" \
  -e POSTGRES_PASSWORD="$DB_PASS" \
  -p "$DB_PORT:5432" \
  "$IMAGE_NAME" \
  -c shared_preload_libraries=pgaudit

echo "Waiting for database to be ready..."
ATTEMPTS=0
MAX_ATTEMPTS=30
until docker exec "$CONTAINER_NAME" pg_isready -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
    echo "Database failed to start after ${MAX_ATTEMPTS} attempts."
    docker logs "$CONTAINER_NAME"
    exit 1
  fi
  sleep 0.5
done

echo "Setting up test fixtures..."
docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -c "
  CREATE EXTENSION IF NOT EXISTS pgaudit;
  CREATE TABLE IF NOT EXISTS public.test_table (
    id bigint PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz DEFAULT now()
  );
  CREATE ROLE tarkin_role;
  GRANT USAGE ON SCHEMA public TO tarkin_role;
  GRANT SELECT ON public.test_table TO tarkin_role;
  GRANT tarkin_role TO tarkin;
"

echo "Running tests..."
TARKIN_TEST_HOST=localhost \
TARKIN_TEST_PORT="$DB_PORT" \
TARKIN_TEST_DB="$DB_NAME" \
TARKIN_TEST_USER="$DB_USER" \
TARKIN_TEST_PASSWORD="$DB_PASS" \
python -m pytest tests/ -v

exit $?
