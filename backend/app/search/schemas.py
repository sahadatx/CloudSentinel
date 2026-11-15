"""Search response contracts."""

from pydantic import BaseModel


class SearchResult(BaseModel):
    type: str
    id: str
    title: str
    subtitle: str
    href: str
    rank: int = 0


class SearchResponse(BaseModel):
    query: str
    results: list[SearchResult]
    total: int = 0
    page: int = 1
    page_size: int = 20
    has_more: bool = False
