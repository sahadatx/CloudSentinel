"""Interactive trusted-operator organization bootstrap command."""

import argparse
import sys
from getpass import getpass

from pydantic import TypeAdapter, ValidationError
from pydantic.networks import EmailStr
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import create_database_engine, create_session_factory
from app.core.models import User
from app.organizations.bootstrap import bootstrap_organization


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="Organization display name")
    parser.add_argument("--slug", required=True, help="Lowercase organization URL/login slug")
    parser.add_argument("--email", required=True, help="Initial administrator email")
    parser.add_argument("--display-name", required=True, help="Initial administrator display name")
    args = parser.parse_args()
    try:
        email = str(TypeAdapter(EmailStr).validate_python(args.email)).lower()
    except ValidationError:
        parser.error("--email must be a valid email address")
    settings = get_settings()
    engine = create_database_engine(settings)
    if engine is None:
        parser.error("CLOUDSENTINEL_DATABASE_URL must point to the migrated PostgreSQL database")
    try:
        with _session(engine) as session:
            existing_user = session.scalar(select(User).where(User.email == email))
            password = None
            if existing_user is None:
                password = getpass("Initial administrator password (12+ characters): ")
                if password != getpass("Confirm password: "):
                    parser.error("Passwords did not match")
            organization = bootstrap_organization(
                session,
                name=args.name,
                slug=args.slug,
                email=email,
                display_name=args.display_name,
                password=password,
            )
    except Exception:
        print(
            "Organization bootstrap failed. Check database configuration and uniqueness.",
            file=sys.stderr,
        )
        return 1
    finally:
        engine.dispose()
    print(
        f"Organization {organization.slug} provisioned with its initial administrator membership."
    )
    return 0


def _session(engine: Engine) -> Session:
    """Return a short-lived unscoped operator session."""
    factory = create_session_factory(engine)
    return factory(info={"allow_unscoped": True})


if __name__ == "__main__":
    raise SystemExit(main())
