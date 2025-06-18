#!/usr/bin/env python

import json
import sys
import time
from datetime import UTC, datetime, timedelta

import click
import requests
from pytimeparse import parse


def escape_wildcard_query(value: str) -> str:
    return value.replace("*", "\\*").replace("?", "\\?")


QUERY_TEMPLATE = {
    "exact": lambda field, value: {
        "match_phrase": {field: {"query": value, "match_entire_field": True}}
    },
    "regex": lambda field, value: {
        "regexp": {field: {"value": value}},
    },
    "has_cs": lambda field, value: {
        "match_phrase": {field: {"query": value}},
    },
    "has": lambda field, value: {
        "wildcard_phrase": {
            field: {"query": escape_wildcard_query(value), "case_insensitive": True}
        }
    },
    "contains_cs": lambda field, value: (
        print("⚠️ Warning: works only on full terms (like has_cs)", file=sys.stderr),
        {"match_phrase": {field: {"query": value}}},
    )[1],
    "contains": lambda field, value: (
        print("⚠️ Warning: works only on full terms (like has)", file=sys.stderr),
        {
            "wildcard_phrase": {
                field: {
                    "query": escape_wildcard_query(value),
                    "case_insensitive": True,
                }
            }
        },
    )[1],
    "contains_cs_slow": lambda field, value: {
        "wildcard_phrase": {
            field: {
                "query": f"*{escape_wildcard_query(value)}*",
                "case_insensitive": False,
            }
        }
    },
    "startswith_cs": lambda field, value: {
        "match_phrase_prefix": {field: {"query": value, "must_start": True}},
    },
    "endswith_cs": lambda field, value: {
        "wildcard_phrase": {
            field: {
                "query": f"*{escape_wildcard_query(value)}",
                "case_insensitive": False,
                "must_end": True,
            }
        }
    },
    "startswith": lambda field, value: {
        "wildcard_phrase": {
            field: {
                "query": f"{escape_wildcard_query(value)}*",
                "case_insensitive": True,
                "must_start": True,
            }
        }
    },
    "endswith": lambda field, value: {
        "wildcard_phrase": {
            field: {
                "query": f"*{escape_wildcard_query(value)}",
                "case_insensitive": True,
                "must_end": True,
            }
        }
    },
    "search_cs": lambda value: {
        "wildcard_phrase": {"_raw": {"query": value, "case_insensitive": False}}
    },
    "search": lambda value: {
        "wildcard_phrase": {"_raw": {"query": value, "case_insensitive": True}}
    },
    "search_field": lambda field, value: {
        "wildcard_phrase": {field: {"query": value, "case_insensitive": False}}
    },
    "search_field_cs": lambda field, value: {
        "wildcard_phrase": {field: {"query": value, "case_insensitive": True}}
    },
}


def create_time_filter(timerange: str, timestamp_field: str):
    """Create a time range filter for the given timerange string."""
    seconds = parse(timerange)
    if seconds is None:
        raise ValueError(f"Invalid timerange format: {timerange}")

    now = datetime.now(UTC)
    start_time = now - timedelta(seconds=seconds)

    return {
        "range": {
            timestamp_field: {
                "gte": start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z",
                "lte": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z",
            }
        }
    }


def build_query(
    base_query: dict, timestamp_filter: dict | None, size: int, should_sort: bool
) -> dict:
    """Build the final Elasticsearch query with filters, sorting, and timerange."""
    filters = [base_query]
    if timestamp_filter:
        filters.append(timestamp_filter)

    # Build query structure
    query = {
        "size": size,
        "query": {"bool": {"filter": filters}},
    }

    if should_sort:
        query["sort"] = [{"timestamp": {"order": "desc"}}]

    return query


@click.command()
@click.argument("mode", type=click.Choice(QUERY_TEMPLATE.keys()))
@click.option(
    "--index", "-i", required=True, help="Index to search (e.g., 'stackoverflow')"
)
@click.option(
    "--field",
    "-f",
    help="Field to search on (not required for 'search' or 'search_cs')",
)
@click.option("--value", "-v", required=True, help="Query value")
@click.option("--size", "-s", default=1, help="Query size")
@click.option(
    "--host",
    default="http://localhost:7280",
    help="Quickwit host (default: localhost:7280)",
)
@click.option("--sort", is_flag=True, help="Sort by timestamp descending")
@click.option(
    "--timerange", "-t", default="24h", help="Time range filter (e.g., 24h, 7d, 30m)"
)
@click.option(
    "--timestamp-field",
    default="timestamp",
    help="timestamp field to filter with (default: timestamp)",
)
@click.option("--all-time", "-A", is_flag=True, help="Don't filter by time")
def main(
    mode: str,
    index: str,
    field: str,
    value: str,
    size: int,
    host: str,
    sort: bool,
    timerange: str,
    timestamp_field: str,
    all_time: bool,
):
    """Run Quickwit search using the Elastic API compatibility layer."""
    if mode in {"search", "search_cs"}:
        base_query = QUERY_TEMPLATE[mode](value)
    else:
        if not field:
            sys.exit("❌ --field is required for this search mode")
        base_query = QUERY_TEMPLATE[mode](field, value)

    timestamp_filter = (
        create_time_filter(timerange, timestamp_field) if not all_time else None
    )
    query = build_query(base_query, timestamp_filter, size, sort)

    url = f"{host}/api/v1/_elastic/{index}/_search"
    try:
        start = time.time()
        resp = requests.post(url, json=query)
        resp.raise_for_status()

        response = resp.json()
        response["query"] = query
        response["duration"] = f"{(time.time() - start)*1000:.2f} ms"
        click.echo(json.dumps(response, indent=2))
    except requests.RequestException as e:
        click.echo(f"query: {json.dumps(query, indent=2)}", err=True)
        click.echo(f"❌ Request failed: {e}, response: {resp.json()}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
