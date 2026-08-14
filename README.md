# Basic short link (auto-generated code)
curl "http://localhost:10000/shorten?url=https://example.com"

# With custom alias
curl "http://localhost:10000/shorten?url=https://example.com&alias=mycool"

# With expiration (in seconds)
curl "http://localhost:10000/shorten?url=https://example.com&expiresIn=3600"

# With campaign tracking
curl "http://localhost:10000/shorten?url=https://example.com&campaign_id=summer2024"

# Complete example with all options
curl "http://localhost:10000/shorten?url=https://github.com&alias=git&expiresIn=604800&campaign_id=devtools"
