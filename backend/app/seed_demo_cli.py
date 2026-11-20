"""CLI entry point for explicitly adding synthetic development data."""

import argparse
import sys

from app.core.config import get_settings
from app.core.database import create_database_engine, create_session_factory
from app.demo_seed import ensure_demo_table_volume, get_demo_tenant_id, seed_demo_data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization-slug", required=True)
    parser.add_argument("--admin-email", required=True)
    parser.add_argument(
        "--minimum-rows",
        type=int,
        choices=(50, 100),
        default=100,
        help="minimum synthetic rows for UI data collections (default: 100)",
    )
    args = parser.parse_args()

    settings = get_settings()
    if settings.app_env != "development":
        parser.error(
            "synthetic demo data can only be seeded when CLOUDSENTINEL_APP_ENV=development"
        )
    engine = create_database_engine(settings)
    if engine is None:
        parser.error("CLOUDSENTINEL_DATABASE_URL must point to the migrated database")
    factory = create_session_factory(engine)
    try:
        with factory(info={"allow_unscoped": True}) as system_session:
            tenant_id = get_demo_tenant_id(system_session, args.organization_slug)
        if tenant_id is None:
            parser.error("organization slug does not exist")
        with factory(info={"tenant_id": tenant_id}) as tenant_session:
            seed_demo_data(
                tenant_session,
                organization_slug=args.organization_slug,
                admin_email=args.admin_email,
            )
            created = ensure_demo_table_volume(
                tenant_session,
                organization_slug=args.organization_slug,
                admin_email=args.admin_email,
                minimum_rows=args.minimum_rows,
            )
            tenant_session.commit()
    except Exception:
        print("Demo data seeding failed; no partial dataset was committed.", file=sys.stderr)
        return 1
    finally:
        engine.dispose()

    created_count = sum(created.values())
    if created_count:
        print(f"Added synthetic demo rows: {created}")
    else:
        print("The synthetic demo dataset already meets the requested table volume.")
    print("Use only for UI exploration; cloud and scan data are synthetic mock records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
