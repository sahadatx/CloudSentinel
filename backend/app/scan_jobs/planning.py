"""Deterministic region/resource work-unit planning for progress reporting."""

from collections.abc import Iterator

from cloudsentinel_scanner.collectors.aws_inventory import (
    AWS_RESOURCE_TYPES,
    GLOBAL_RESOURCE_TYPES,
)


def planned_units(resource_types: list[str], regions: list[str]) -> Iterator[tuple[str, str]]:
    """Yield each selected global resource type once and regional type per selected region."""
    ordered_types = [kind for kind in AWS_RESOURCE_TYPES if kind in set(resource_types)]
    for kind in ordered_types:
        if kind in GLOBAL_RESOURCE_TYPES:
            yield kind, regions[0]
        else:
            for region in regions:
                yield kind, region
