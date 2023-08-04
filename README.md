# These three environment variables must be set before running docker compose up -d
export C2_API_KEY="key_here"

export C2_API_URL="url_here"

export MISP_FEED_API_KEY="key_here"

# Code inspired from
https://github.com/MISP/PyMISP/tree/main/examples/feed-generator-from-redis

generator.py and settings.py are changed as little as possible
