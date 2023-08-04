"""Main module, FastAPI runs from here"""
import asyncio
import json
import os
import time
from typing import Dict, Union

import requests
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.background import BackgroundTasks
from fastapi.responses import JSONResponse
from requests.exceptions import ConnectionError as requestsConnectionError

from .redis_db import event_endpoint_data, hashes_endpoint_data, manifest_endpoint_data
from .service import generate_feed_event, update_feed

MISP_FEED_API_KEY = os.environ["MISP_FEED_API_KEY"]

# Create fastapi app
# Disable swagger and docs endpoints for now
app = FastAPI(docs_url=None, redoc_url=None)


@app.on_event("startup")
async def app_startup() -> None:
    """Start the permanent event update task

    Returns:
    None
    """

    asyncio.create_task(update_feed())


@app.get("/manifest.json")
async def get_manifest(request: Request) -> Response:
    """Get /manifest.json, GET method.

    Returns:
    fastapi.Response
    """

    if "Api-Key" not in request.headers or request.headers["Api-Key"] != MISP_FEED_API_KEY:
        raise HTTPException(status_code=401, detail="Api-Key header invalid or missing")

    manifest_data = await manifest_endpoint_data()
    if manifest_data is None:
        return Response(status_code=500, content='{"detail":"Internal server error"}', media_type="application/json")

    return JSONResponse(status_code=200, content=manifest_data)


@app.get("/hashes.csv")
async def get_hashes(request: Request) -> Response:
    """Get /hashes.csv, GET method.

    Returns:
    fastapi.Response
    """

    if "Api-Key" not in request.headers or request.headers["Api-Key"] != MISP_FEED_API_KEY:
        raise HTTPException(status_code=401, detail="Api-Key header invalid or missing")

    hashes_data = await hashes_endpoint_data()
    if hashes_data is None:
        return Response(status_code=500, content='{"detail":"Internal server error"}', media_type="application/json")

    return Response(status_code=200, content=hashes_data, media_type="text/csv")


@app.get("/{event}.json")
async def get_event(event: str, request: Request) -> Response:
    """Get /{event_id}.json, GET method.

    Returns:
    fastapi.Response
    """

    if "Api-Key" not in request.headers or request.headers["Api-Key"] != MISP_FEED_API_KEY:
        raise HTTPException(status_code=401, detail="Api-Key header invalid or missing")

    event_data = await event_endpoint_data(event)
    if event_data is None:
        return Response(status_code=404, content='{"detail":"Not Found"}', media_type="application/json")

    return JSONResponse(status_code=200, content=json.loads(event_data))
