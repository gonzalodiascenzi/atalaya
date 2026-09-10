#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  ATALAYA // ¿El esquema de la base coincide con models.py?
#
#  Guarda contra el olvido más común: cambiar un modelo y no generar la
#  migración. Si autogenerate detecta diferencias, lo desplegado no es lo
#  que el código cree que es.
#
#  FALLA CERRADO. La versión anterior buscaba el archivo generado por
#  nombre (`*ci-check*.py`), pero Alembic nombra los archivos por el slug
#  del mensaje, no por el rev-id: el patrón nunca coincidía, grep fallaba
#  sobre un archivo inexistente, el `if` daba falso y el control informaba
#  "✓ coincide" SIEMPRE. Un guardián que no puede fallar no guarda nada.
#
#  Ahora el archivo se localiza por su contenido, y si no aparece, falla.
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

REV="deriva$(date +%s)"
cd "$(dirname "$0")/.."

limpiar() { grep -l "revision: str = '${REV}'" migrations/versions/*.py 2>/dev/null | xargs -r rm -f; }
trap limpiar EXIT

if ! SALIDA="$(alembic revision --autogenerate -m "control de deriva" --rev-id "$REV" 2>&1)"; then
  echo "✗ Alembic no pudo comparar el esquema. Falla cerrado. Motivo:"
  echo "$SALIDA" | grep -E "Error|error|FAILED|Can't|not up to date" | tail -3 | sed 's/^/    /'
  exit 1
fi

ARCHIVO="$(grep -l "revision: str = '${REV}'" migrations/versions/*.py || true)"
if [[ -z "$ARCHIVO" ]]; then
  echo "✗ No se pudo generar el archivo de control. Falla cerrado: sin"
  echo "  evidencia de que el esquema coincida, no se asume que coincide."
  exit 1
fi

if grep -qE "op\.(create_table|drop_table|add_column|drop_column|alter_column|create_index|drop_index|create_unique_constraint|drop_constraint)" "$ARCHIVO"; then
  echo "✗ Los modelos cambiaron sin migración. Diferencias detectadas:"
  grep -E "^\s+op\." "$ARCHIVO" | sed 's/^/    /'
  echo ""
  echo "  Generala con:  make db-revision M=\"descripcion del cambio\""
  exit 1
fi

echo "✓ El esquema de la base coincide exactamente con models.py"
