from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from pymisp import MISPEvent, MISPOrganisation
from redis.asyncio.client import Redis

from . import settings


async def redis_connection() -> Redis[str]:
    """Get a redis connection"""

    if TYPE_CHECKING:
        conn = Redis[str](
            host=settings.host,
            port=settings.port,
            db=settings.db,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )
    else:
        conn = Redis(
            host=settings.host,
            port=settings.port,
            db=settings.db,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )

    if isinstance(conn, Redis) and (await conn.ping()):
        return conn

    raise ValueError("ERROR: Problem with data from redis")


async def redis_save() -> None:
    """Save redis data to file"""

    conn = await redis_connection()
    ret = await conn.bgsave()
    await conn.close()


# Example
# 89.47.184.5 - - [11/Apr/2023 10:19:00] "GET /manifest.json HTTP/1.1" 200 -
async def manifest_endpoint_data() -> Optional[str]:
    """Get the misp manifest from the redis connection"""

    conn = await redis_connection()
    ret = await conn.get(settings.manifest_key)

    await conn.close()

    if ret is None:
        return None

    if isinstance(ret, str) and len(ret) > 3:
        return ret

    raise ValueError("ERROR: Problem with data from redis")


# Example
# 89.47.184.5 - - [11/Apr/2023 10:19:00] "GET /hashes.csv HTTP/1.1" 200 -
async def hashes_endpoint_data() -> str:
    """Get the misp hashes from the redis connection"""

    conn = await redis_connection()
    ret = await conn.lrange(f"{settings.hashes_key}", 0, -1)

    await conn.close()

    if isinstance(ret, list) and len(ret) > 0:
        return "".join(ret)

    raise ValueError("ERROR: Problem with data from redis")


# Example
# 89.47.184.5 - - [11/Apr/2023 10:19:00] "GET /14a6aa68-023f-4152-ad61-fa87e876b31b.json HTTP/1.1" 200 -
async def event_endpoint_data(uuid: str) -> Optional[str]:
    """Get the misp event from the redis connection"""

    conn = await redis_connection()
    ret = await conn.get(f"{settings.event_prefix_key}{uuid}")

    await conn.close()

    if ret is None:
        return None

    if isinstance(ret, str) and len(ret) > 3:
        return ret

    raise ValueError("ERROR: Problem with data from redis")


async def redis_recreate_manifest() -> Dict[str, Any]:
    keys: List[str] = []
    manifest: Dict[str, Any] = {}

    conn = await redis_connection()

    cur, curr_keys = await conn.scan(cursor=0, match=f"{settings.event_prefix_key}*", count=30)
    keys.extend(curr_keys)
    while cur != 0:
        cur, curr_keys = await conn.scan(cursor=cur, match=f"{settings.event_prefix_key}*", count=30)
        keys.extend(curr_keys)

    for key in keys:
        event_data = await event_endpoint_data(key.replace(settings.event_prefix_key, ""))
        if event_data is None:
            raise ValueError("ERROR: Problem with data from redis")

        event_json_data = json.loads(event_data)
        event = MISPEvent()
        event.from_dict(**event_json_data["Event"])
        manifest.update(event.manifest)

    await conn.set(settings.manifest_key, json.dumps(manifest))
    await conn.close()
    return manifest
