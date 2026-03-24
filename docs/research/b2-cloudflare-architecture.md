# Backblaze B2 + Cloudflare Architecture Research

## Table of Contents

1. [Bandwidth Alliance Foundation](#bandwidth-alliance-foundation)
2. [Cloudflare Workers with B2](#cloudflare-workers-with-b2)
3. [Cloudflare CDN Caching with B2](#cloudflare-cdn-caching-with-b2)
4. [Security Architecture](#security-architecture)
5. [Upload Path Architecture](#upload-path-architecture)
6. [Terms of Service Considerations](#terms-of-service-considerations)
7. [Pricing Analysis](#pricing-analysis)
8. [Real-World Architecture Patterns](#real-world-architecture-patterns)
9. [Sources](#sources)

---

## Bandwidth Alliance Foundation

Backblaze and Cloudflare are founding members of the Bandwidth Alliance. The partnership provides:

- **Zero egress fees** from B2 to Cloudflare CDN for all Cloudflare plan tiers (including Free).
- Direct peering/interconnection between Backblaze data centers and Cloudflare's network, enabling near-instant data transfers.
- The zero-fee arrangement applies to data flowing from B2 to Cloudflare -- it is not a general egress waiver. Traffic from B2 to non-Cloudflare destinations still incurs standard egress ($0.01/GB beyond the free 3x-storage allowance).

**B2 Storage Regions with S3 Endpoints:**
- US West: `s3.us-west-001.backblazeb2.com` through `s3.us-west-004.backblazeb2.com`
- US East: `s3.us-east-005.backblazeb2.com`
- EU Central: `s3.eu-central-003.backblazeb2.com`

---

## Cloudflare Workers with B2

### Two Official Reference Implementations

Backblaze maintains two official Worker templates on GitHub:

#### 1. `cloudflare-b2` -- Read-Only Proxy for Private Buckets

**Purpose:** Allows unauthenticated end users to download files from a private B2 bucket through a Worker that signs requests at the edge.

**Request Flow:**
1. User's browser sends unsigned GET/HEAD to Worker endpoint (e.g., `https://files.example.com/image.png`)
2. Worker receives the request, rewrites the hostname to the B2 S3 endpoint
3. Worker signs the request using AWS V4 signature with stored B2 credentials
4. Signed request forwarded to B2
5. B2 validates signature, returns content
6. Worker streams response directly to user (no buffering into memory)

**Key implementation details from the source code (`index.js`):**

```javascript
import { AwsClient } from 'aws4fetch'

// Headers that must NOT be included in the signature because Cloudflare
// modifies them between incoming and outgoing requests
const UNSIGNABLE_HEADERS = [
    'x-forwarded-proto',
    'x-real-ip',
    'accept-encoding',    // CF changes "gzip, br" to "gzip"
    'if-match',
    'if-modified-since',
    'if-none-match',
    'if-range',
    'if-unmodified-since',
];

// Also strips all cf-* headers
```

**Bucket routing modes** (configured via `BUCKET_NAME` env var):
- Fixed name: `BUCKET_NAME = "my-bucket"` -> all requests go to `my-bucket.s3.region.backblazeb2.com`
- Path-based: `BUCKET_NAME = "$path"` -> first URL path segment is the bucket name
- Host-based: `BUCKET_NAME = "$host"` -> first subdomain is the bucket name

**Environment variables (`wrangler.toml`):**
```toml
[vars]
B2_APPLICATION_KEY_ID = "<key id>"
B2_ENDPOINT = "s3.us-west-004.backblazeb2.com"
BUCKET_NAME = "my-bucket"          # or "$path" or "$host"
ALLOW_LIST_BUCKET = "false"        # deny ListObjects by default
RCLONE_DOWNLOAD = "false"          # strip "file/" prefix for rclone compat
# ALLOWED_HEADERS = ["content-type", "date", "host", "range", ...]
```

**Secret (never in wrangler.toml):**
```bash
echo "<your b2 application key>" | wrangler secret put B2_APPLICATION_KEY
```

**Range request workaround:** For files larger than ~2GB, Cloudflare may return the entire file instead of the requested range. The Worker includes retry logic (3 attempts) that aborts the response and retries if the `content-range` header is missing:

```javascript
if (signedRequest.headers.has("range")) {
    let attempts = RANGE_RETRY_ATTEMPTS;
    do {
        let controller = new AbortController();
        response = await fetch(signedRequest.url, {
            method: signedRequest.method,
            headers: signedRequest.headers,
            signal: controller.signal,
        });
        if (response.headers.has("content-range")) {
            break;
        } else if (response.ok) {
            attempts -= 1;
            if (attempts > 0) controller.abort();
        } else {
            break;
        }
    } while (attempts > 0);
}
```

**HEAD request workaround:** Cloudflare appears to change HEAD methods to GET on outgoing requests, breaking the signature. The Worker signs all requests as GET, then creates a bodyless response for HEAD requests.

#### 2. `cloudflare-b2-proxy` -- Full S3 Proxy with Signature Passthrough

**Purpose:** Acts as a transparent S3 proxy. Clients sign requests with the same B2 credentials configured in the Worker. The Worker validates the incoming signature, re-signs for B2, and forwards.

**Request Flow:**
1. Client (SDK, CLI, etc.) signs request with B2 credentials and sends to Worker endpoint
2. Worker parses the incoming AWS V4 `Authorization` header
3. Worker verifies the signature matches by re-computing it locally
4. Worker strips Cloudflare-injected headers, re-signs for B2's endpoint
5. Request forwarded to B2, response returned to client
6. Optionally, a webhook notification fires asynchronously via `event.waitUntil()`

**Signature verification code:**
```javascript
async function verifySignature(request) {
    const authorization = request.headers.get('Authorization');
    // Parse: AWS4-HMAC-SHA256 Credential=.../...,SignedHeaders=...,Signature=...
    const re = /^AWS4-HMAC-SHA256 Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=(.+)$/;
    let [ , credential, signedHeaders, signature] = authorization.match(re);

    // Verify key ID matches
    if (credential.split('/')[0] != AWS_ACCESS_KEY_ID) {
        throw new SignatureInvalidException();
    }

    // Re-sign with same timestamp and compare signatures
    const signedRequest = await aws.sign(request.url, {
        method: request.method,
        headers: headersToSign,
        body: request.body,
        aws: { datetime: datetime, allHeaders: true }
    });

    const [ , , , generatedSignature] = signedRequest.headers.get('Authorization').match(re);
    if (signature !== generatedSignature) {
        throw new SignatureInvalidException();
    }
}
```

**Webhook notification payload:**
```json
{
    "contentLength": 14,
    "contentType": "text/plain",
    "method": "PUT",
    "signatureTimestamp": "20220224T193204Z",
    "status": 200,
    "url": "https://s3.us-west-004.backblazeb2.com/my-bucket/file.txt"
}
```

### Signing Library

Both implementations use **`aws4fetch`** (npm: `aws4fetch@^1.0.20`), a compact AWS V4 signing library purpose-built for Service Worker / Cloudflare Workers environments. It uses the Web Crypto API (SubtleCrypto) rather than Node.js crypto, making it compatible with the Workers runtime. Informal testing shows negligible overhead from the signing step.

---

## Cloudflare CDN Caching with B2

### The Authorization Header Problem

**Critical issue:** Cloudflare's CDN automatically sets `cf-cache-status: BYPASS` for any request containing an `Authorization` header, regardless of `cacheEverything` settings. This means:

- Requests signed for B2 (which contain `Authorization`) will NOT be cached by default.
- The `cacheEverything` fetch option does NOT override this behavior.

### Solutions for Caching Authenticated Content

**Approach 1: Cache API with Custom Cache Keys (Enterprise)**

Use the `cacheKey` option in the `cf` object to strip authentication parameters:

```javascript
const response = await fetch(signedRequest, {
    cf: {
        cacheEverything: true,
        cacheTtl: 86400,
        cacheKey: url.hostname + url.pathname  // Strip auth query params
    }
});
```

Note: `cacheKey` is an Enterprise-only feature.

**Approach 2: Workers Cache API (All Plans)**

Use the Cache API to manually cache responses under a clean URL:

```javascript
const cache = caches.default;
const cacheKey = new Request(url.toString().split('?')[0]); // Strip query params

let response = await cache.match(cacheKey);
if (!response) {
    response = await fetch(signedRequest);
    // Clone and cache the response
    const responseToCache = new Response(response.body, response);
    responseToCache.headers.set('Cache-Control', 'public, max-age=86400');
    event.waitUntil(cache.put(cacheKey, responseToCache.clone()));
}
return response;
```

**Approach 3: HMAC Token Validation + Stripped Cache Key**

Validate requests via HMAC at the Worker, then fetch from B2 using a URL-derived cache key that excludes auth tokens:

```javascript
// Validate HMAC token from query params
// ...
let cache_key = url.host + url.pathname;
const response = await fetch(request, {
    cf: { cacheKey: cache_key },
    headers: headers,
});
```

### Cache-Control Headers from B2

B2 buckets created after September 8, 2021 do NOT include any cache-control headers by default. You must explicitly set them.

**Bucket-level cache-control (applies to all files in the bucket):**

In Backblaze dashboard -> Bucket Settings -> Bucket Info:
```json
{"Cache-Control": "public, max-age=86400"}
```

**Per-file cache-control:** Can be set via the `b2_upload_file` API or S3 PutObject with appropriate headers.

### Cloudflare Cache Rules Configuration

**Cache Rules (replaces deprecated Page Rules):**

For B2 content served through a custom domain:

1. **Match expression:** `(http.host eq "files.example.com")`
2. **Cache eligibility:** Eligible for cache
3. **Edge TTL:** Override origin, set to 7 days or 1 month
4. **Browser TTL:** Override origin, set to 1 day
5. **Cache Level:** Cache Everything (important: B2 returns many non-standard content types that Cloudflare would not cache by default)
6. **Origin Cache Control:** ON (critical -- this tells Cloudflare to respect Cache-Control headers from B2)

**Status-based TTLs in Workers:**
```javascript
cacheTtlByStatus: {
    "200-299": 86400,   // Cache successful responses for 1 day
    "404": 60,          // Cache 404s briefly
    "500-599": 0        // Never cache errors
}
```

### Cache Purge/Invalidation Strategies

1. **Purge by URL:** Single-file purge via Cloudflare API or dashboard. Recommended for targeted invalidation.
   ```
   POST https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache
   {"files": ["https://files.example.com/image.png"]}
   ```

2. **Purge by prefix:** Enterprise only. Purge all files under a URL prefix.

3. **Purge everything:** Available on all plans, but clears the entire zone cache.

4. **Versioned URLs (recommended):** Use content-addressed filenames (e.g., `image-a1b2c3.png` or `image.png?v=abc123`) to sidestep cache invalidation entirely. New versions get new URLs, old cached versions expire naturally.

### Custom Domain Setup (CNAME to B2)

1. **Create CNAME record** in Cloudflare DNS:
   - Name: `files` (for `files.example.com`)
   - Target: `f004.backblazeb2.com` (your B2 bucket's friendly URL hostname)
   - Proxy: Enabled (orange cloud)

2. **Set SSL/TLS mode** to "Full (strict)" -- B2 requires HTTPS.

3. **Disable Automatic Signed Exchanges (SXGs)** -- incompatible with B2.

4. **Create Transform Rule (URL Rewrite):**
   - When: `(http.host eq "files.example.com" and not starts_with(http.request.uri.path, "/file/my-bucket"))`
   - Rewrite path: `concat("/file/my-bucket", http.request.uri.path)`

   This transforms `https://files.example.com/photo.jpg` into `https://f004.backblazeb2.com/file/my-bucket/photo.jpg` at the edge.

### Response Header Cleanup

Create a Modify Response Header rule to remove B2-specific headers that leak internal details:

Remove these headers:
- `x-bz-file-name`
- `x-bz-file-id`
- `x-bz-content-sha1`
- `x-bz-upload-timestamp`
- `x-bz-info-src_last_modified_millis`

Optionally synthesize an ETag from B2 headers:
```
concat(http.response.headers["x-bz-content-sha1"][0],
       http.response.headers["x-bz-info-src_last_modified_millis"][0],
       http.response.headers["x-bz-file-id"][0])
```

---

## Security Architecture

### Preventing Direct B2 Access

**Strategy 1: Private Bucket (Recommended)**

Make the bucket private. This is the strongest approach:
- Anonymous access returns 401 Unauthorized
- All requests must be signed with a valid application key
- The Worker holds the signing credentials; end users never see them
- Even if someone discovers the B2 endpoint hostname, they cannot access content without credentials

**Strategy 2: Public Bucket + URL Obfuscation (Weaker)**

Keep bucket public but use Transform Rules to hide the bucket name:
- Users see `https://files.example.com/photo.jpg`
- Transform Rule rewrites to `/file/bucket-name/photo.jpg` at the edge
- Bucket name is not exposed in the user-facing URL
- Weakness: determined attackers can still discover the B2 endpoint and access content directly

### B2 Application Key Least Privilege

Create a dedicated application key for the Worker with minimal permissions:

- **Read-Only** capability (no write, no delete)
- **Single-bucket** restriction (not account-wide)
- **File prefix** restriction if needed (e.g., only files under `public/`)
- **Expiration** configured if appropriate (1 second to never; expired keys cannot generate auth tokens)

### Signed URL Approaches

#### B2 S3 Presigned URLs

Generated server-side, given to clients for time-limited access:

```bash
# Via AWS CLI
aws s3 presign s3://my-bucket/file.txt \
    --endpoint-url https://s3.us-west-004.backblazeb2.com \
    --expires-in 3600
```

- Expiration: 1 second to 7 days (configurable)
- One URL per file per generation
- Filename embedded in the URL
- Standard S3 presigned URL format

#### B2 Native API Authorization Tokens

Generated via `b2_get_download_authorization`:

- Fixed 24-hour validity or until endpoint rejection
- Can authorize access to a bucket or prefix
- Token passed as query parameter: `?Authorization=<token>`
- Single token can be reused for multiple file downloads

#### Cloudflare Worker HMAC Signed URLs

Generate time-limited HMAC tokens at the application layer:

```
https://files.example.com/photo.jpg?verify=1711234567-a1b2c3d4e5f6
```

Worker validates the HMAC before proxying to B2. This pattern:
- Decouples auth from B2's native auth (Worker manages its own tokens)
- Allows custom expiration windows
- Enables caching (cache key strips the `verify` parameter)
- Requires a shared secret between your application server and the Worker

### Cloudflare Access / Zero Trust Integration

Not directly documented for B2 specifically, but the pattern works:

1. Place `files.example.com` behind a Cloudflare Access policy
2. Require authentication (SSO, one-time PIN, service token, etc.)
3. Access validates identity before the request reaches the Worker
4. Worker then signs and proxies to B2

This adds an authentication layer without B2 knowing about it. Useful for internal tools, admin panels, or gated content.

**Limitation:** Cloudflare Access has a file upload limit that may restrict large uploads through the Access proxy.

---

## Upload Path Architecture

### Should Uploads Go Through Cloudflare?

**Short answer: Usually no for large files, yes for small files if you want the proxy pattern.**

**Direct-to-B2 upload (recommended for most cases):**

1. Client requests a presigned upload URL from your backend
2. Backend generates S3 presigned URL using B2 credentials (never exposed to client)
3. Client PUTs file directly to B2 via the presigned URL
4. B2 ingress is free -- no egress fee applies to inbound data

**Advantages:**
- No Cloudflare body size limits
- No Worker CPU time consumed
- B2 ingress is always free regardless of path
- Supports files up to 5GB per single PUT (or unlimited via multipart)

**Upload through Cloudflare Worker:**

Possible but constrained:
- **Free/Pro plan:** 100MB request body limit
- **Business plan:** 200MB limit
- **Enterprise plan:** 500MB limit (can be increased)
- Worker must stream the body to B2 to avoid memory limits
- CPU time limit applies (10ms free, 5min paid)

### Presigned URL Upload Architecture

**S3 Presigned URL approach (recommended):**

```
Browser -> Your Backend: "I want to upload photo.jpg"
Backend -> Browser: presigned PUT URL (valid 1 hour)
Browser -> B2 directly: PUT photo.jpg via presigned URL
```

Backend code to generate presigned upload URL:
```python
import boto3
from botocore.config import Config

s3 = boto3.client('s3',
    endpoint_url='https://s3.us-west-004.backblazeb2.com',
    aws_access_key_id=B2_KEY_ID,
    aws_secret_access_key=B2_APP_KEY,
    config=Config(signature_version='s3v4')
)

url = s3.generate_presigned_url('put_object',
    Params={'Bucket': 'my-bucket', 'Key': 'uploads/photo.jpg'},
    ExpiresIn=3600
)
```

**B2 Native API approach:**

```
Browser -> Your Backend: "I want to upload a file"
Backend -> B2: b2_get_upload_url (with bucket ID)
Backend -> Browser: upload URL + auth token (valid 24h)
Browser -> B2: POST file with auth token
```

- Single token supports multiple file uploads
- Filename specified as HTTP header during upload
- Uses SubtleCrypto for SHA1 content hashing in-browser

### CORS Configuration for Browser Uploads

Required when browsers upload directly to B2:

```json
[
    {
        "corsRuleName": "browserUpload",
        "allowedOrigins": ["https://app.example.com"],
        "allowedOperations": ["s3_put", "b2_upload_file", "b2_upload_part"],
        "allowedHeaders": [
            "authorization",
            "content-type",
            "x-bz-file-name",
            "x-bz-content-sha1"
        ],
        "maxAgeSeconds": 3600
    }
]
```

### Large File / Multipart Upload

For files > 5GB, B2 requires multipart upload:
- Part size: 5MB to 5GB each
- S3 Multipart Upload API is supported
- B2 Native API equivalents: `b2_start_large_file`, `b2_get_upload_part_url`, `b2_upload_part`, `b2_finish_large_file`
- Each part can be uploaded in parallel
- No tus protocol support documented for B2 directly

### Tus Protocol

B2 does not natively support the tus resumable upload protocol. If you need tus:
- Implement a tus server (e.g., tusd) that writes to B2 as its storage backend
- Or use a Cloudflare Worker as a tus endpoint that reassembles and forwards to B2
- This adds complexity and is not the standard B2 integration pattern

---

## Terms of Service Considerations

### Critical: Cloudflare CDN Content Restrictions

As of May 2023, Cloudflare updated their terms (removing the infamous Section 2.8) with the following rules:

**Allowed through Cloudflare CDN:**
- Video, images, and large non-HTML files **hosted by Cloudflare services** (R2, Stream, Images)
- HTML content from any origin
- Content served through Workers (Workers has its own supplemental terms)

**Restricted on Cloudflare CDN:**
- "Video and large files hosted outside of Cloudflare will still be restricted on our CDN"

**What this means for B2:**
- Using Cloudflare purely as a CDN/reverse proxy for B2-hosted video or predominantly non-HTML content is technically against the updated terms.
- **However:** The B2 + Cloudflare Bandwidth Alliance partnership is still actively promoted by both companies, and Backblaze's marketing explicitly describes serving "videos, photos, and other assets" through Cloudflare.
- Using **Cloudflare Workers** to proxy B2 content appears to be compliant, as Workers is a compute service with its own terms, not just CDN caching.
- The practical enforcement boundary is unclear. Small-to-medium image hosting through B2 + Cloudflare is extremely common and widely documented by both companies.

**Safest approaches:**
1. Use a Cloudflare Worker (not just CDN Transform Rules) to proxy B2 content
2. For heavy video workloads, consider Cloudflare Stream or R2 instead
3. For image-heavy workloads at scale, consider Cloudflare Images or R2
4. Mixed HTML + assets (typical web application) is clearly fine

---

## Pricing Analysis

### Backblaze B2 Costs

| Item | Price |
|------|-------|
| Storage | $6/TB/month (first 10GB free) |
| B2 Overdrive (high-perf tier) | $15/TB/month |
| Downloads to Cloudflare | **$0** (Bandwidth Alliance) |
| Downloads to other destinations | Free up to 3x stored data/month, then $0.01/GB |
| Class A transactions (writes) | Free |
| Class B transactions (reads) | 2,500/day free, then $0.004/10,000 |
| Class C transactions (list/other) | 2,500/day free, then $0.004/1,000 |
| Ingress (uploads) | Free |

### Cloudflare Workers Costs

| Item | Free Tier | Paid ($5/mo) |
|------|-----------|-------------|
| Requests | 100,000/day | 10M/month included, then $0.30/M |
| CPU time | 10ms/invocation | 30M CPU-ms/month included, then $0.02/M CPU-ms |
| Data transfer | N/A (no egress charge) | N/A (no egress charge) |
| KV reads | 100,000/day | $0.50/M |
| KV writes | 1,000/day | $5.00/M |

**Workers does not charge for data transfer/bandwidth.** Only requests and CPU time are billed.

### Cost Example: Image Hosting

10GB stored in B2 with 1M image downloads/month through a Cloudflare Worker:

- B2 storage: $0 (free tier)
- B2 egress to Cloudflare: $0 (Bandwidth Alliance)
- B2 Class B transactions: ~$0.004 per 10K = ~$0.40/month (assuming ~10% cache miss rate)
- Cloudflare Worker: $5/month base (or free tier if < 100K req/day)
- **Total: $0.40 to $5.40/month** for serving 1M images

### Cost Comparison vs. AWS S3 + CloudFront

Same workload (10GB, 1M downloads, ~100MB average file egress):
- S3 storage: ~$0.23
- S3 egress: $9.00/100GB (if average 100KB/file = 100GB)
- CloudFront: varies but typically $8.50/100GB
- **Total: ~$17-18/month**

The B2 + Cloudflare path is roughly **3-40x cheaper** depending on workload shape.

---

## Real-World Architecture Patterns

### Pattern 1: Image/Asset CDN for a Web Application

```
                    +-----------------+
                    |   User Browser  |
                    +--------+--------+
                             |
                    +--------v--------+
                    | Cloudflare CDN  |  <-- Cache hit? Return cached.
                    |  (Custom Domain)|
                    +--------+--------+
                             |  Cache miss
                    +--------v--------+
                    | Cloudflare      |  <-- Signs request, proxies to B2
                    | Worker          |
                    +--------+--------+
                             |
                    +--------v--------+
                    | Backblaze B2    |  <-- Private bucket
                    | (S3 API)        |
                    +-----------------+
```

**Setup:**
1. Private B2 bucket with `{"Cache-Control": "public, max-age=31536000"}` for immutable assets
2. CNAME `cdn.example.com` -> B2 endpoint, proxied through Cloudflare
3. Worker on `cdn.example.com` route: signs requests, sets `cf.cacheEverything: true, cf.cacheTtl: 86400`
4. Response header rule strips `x-bz-*` headers
5. Application generates URLs like `https://cdn.example.com/images/photo-abc123.jpg`

**Upload path:**
- Application backend generates S3 presigned PUT URL
- Client uploads directly to B2 (bypassing Cloudflare)
- On success, application records the object key in its database

### Pattern 2: Private File Sharing (Signed URLs)

```
User -> App Backend: "Give me download link for report.pdf"
App Backend: generates HMAC-signed URL valid for 1 hour
App Backend -> User: https://files.example.com/reports/report.pdf?verify=1711234567-hmac

User -> Cloudflare Worker: GET with HMAC token
Worker: validates HMAC, checks expiration
Worker: signs request for B2, fetches file
Worker -> User: streams file content
```

**Key details:**
- Worker validates the HMAC token independently from B2 auth
- Cache key is `files.example.com/reports/report.pdf` (stripped of auth params)
- Subsequent requests with different valid tokens hit the cache
- Expired or invalid tokens get 403 without ever touching B2

### Pattern 3: Backup/Archive Storage (No CDN)

For backup workloads where CDN caching is not needed:

```
Backup Agent -> B2 (direct): Upload via S3 API or b2 CLI
                              Uses write-only application key
                              Lifecycle rules auto-delete after N days

Restore:
Admin -> B2 (direct): Download via S3 API or b2 CLI
                       Uses read-only application key
```

Cloudflare is not involved at all -- backups go directly to B2 via the S3 API. The Bandwidth Alliance benefit does not apply, but ingress (uploads) is free anyway.

For restore scenarios where you need to download large amounts of data, consider:
- Downloading through a Cloudflare Worker to avoid egress fees
- Or accepting the egress cost ($0.01/GB beyond free allowance)

### Pattern 4: Video Hosting

```
Upload:  Client -> Presigned URL -> B2 (direct, free ingress)

Playback:
  Client -> Cloudflare Worker -> B2

  Worker handles:
  - Authentication/authorization
  - Range request retries (2GB+ workaround)
  - Signed request generation
  - Cache-Control headers for segments
```

**Caveats:**
- Cloudflare's updated ToS restricts video served from external origins through their CDN
- For production video at scale, Cloudflare Stream or R2 may be more appropriate
- For low-volume video (internal tools, small audience), the B2 + Worker pattern works in practice
- Range request support is critical for video seeking -- the Worker handles the retry logic

### Pattern 5: Multi-Bucket Routing

Using `BUCKET_NAME = "$host"` or `"$path"` mode:

```
images.files.example.com/photo.jpg  -> images bucket
videos.files.example.com/clip.mp4   -> videos bucket
docs.files.example.com/report.pdf   -> docs bucket
```

Or with path-based routing:
```
files.example.com/images/photo.jpg  -> images bucket
files.example.com/videos/clip.mp4   -> videos bucket
files.example.com/docs/report.pdf   -> docs bucket
```

Each bucket can have its own application key with appropriate permissions, though the single Worker currently uses one key. For per-bucket keys, you would need to extend the Worker to select credentials based on the resolved bucket name.

---

## Sources

- [Backblaze + Cloudflare Bandwidth Alliance Partnership](https://www.backblaze.com/blog/backblaze-and-cloudflare-partner-to-provide-free-data-transfer/)
- [Cloudflare Technology Partners: Backblaze](https://www.cloudflare.com/partners/technology-partners/backblaze/)
- [Backblaze: Deliver Public B2 Content Through Cloudflare CDN](https://www.backblaze.com/docs/cloud-storage-deliver-public-backblaze-b2-content-through-cloudflare-cdn)
- [Backblaze: Deliver Private B2 Content Through Cloudflare CDN](https://www.backblaze.com/docs/cloud-storage-deliver-private-backblaze-b2-content-through-cloudflare-cdn)
- [Backblaze Blog: How to Serve Data From a Private Bucket with a Cloudflare Worker](https://www.backblaze.com/blog/how-to-serve-data-from-a-private-bucket-with-a-cloudflare-worker/)
- [Backblaze Blog: Free Image Hosting with Cloudflare Transform Rules and B2](https://www.backblaze.com/blog/free-image-hosting-with-cloudflare-transform-rules-and-backblaze-b2/)
- [Cloudflare Blog: Backblaze B2 and the S3 Compatible API on Cloudflare](https://blog.cloudflare.com/backblaze-b2-and-the-s3-compatible-api-on-cloudflare/)
- [Cloudflare Blog: Goodbye Section 2.8 -- Updated Terms of Service](https://blog.cloudflare.com/updated-tos/)
- [GitHub: backblaze-b2-samples/cloudflare-b2 (Private Bucket Worker)](https://github.com/backblaze-b2-samples/cloudflare-b2)
- [GitHub: backblaze-b2-samples/cloudflare-b2-proxy (S3 Proxy Worker)](https://github.com/backblaze-b2-samples/cloudflare-b2-proxy)
- [GitHub: backblaze-b2-samples/b2-browser-upload (Browser Upload)](https://github.com/backblaze-b2-samples/b2-browser-upload)
- [GitHub: aws4fetch Signing Library](https://github.com/mhart/aws4fetch)
- [Cloudflare Workers Pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Cloudflare Workers: Cache Using Fetch](https://developers.cloudflare.com/workers/examples/cache-using-fetch/)
- [Cloudflare: Cache Purge Documentation](https://developers.cloudflare.com/cache/how-to/purge-cache/)
- [Cloudflare: How Workers Interact with Cache](https://developers.cloudflare.com/workers/reference/how-the-cache-works/)
- [Backblaze: Application Key Capabilities](https://www.backblaze.com/docs/cloud-storage-application-key-capabilities)
- [Backblaze: Create and Manage Application Keys](https://www.backblaze.com/docs/cloud-storage-create-and-manage-application-keys)
- [Backblaze B2: S3 Presigned URL Support](https://help.backblaze.com/hc/en-us/articles/360047815993-Does-the-B2-S3-Compatible-API-support-Pre-Signed-URLs)
- [Backblaze B2: Transaction Pricing](https://www.backblaze.com/cloud-storage/transaction-pricing)
- [Gist: Properly Cache B2 Content with Cloudflare](https://gist.github.com/davelevine/795df9e7d14aabda4d1bdfc6b66158bc)
- [Gist: Access Private B2 from Cloudflare Transform Rules](https://gist.github.com/lzjluzijie/3f1294f47755972f9bcd68f90ffc0b73)
- [Gist: Practically Free CDN with B2](https://gist.github.com/charlesroper/f2da6152d6789fa6f25e9d194a42b889)
- [Signed URLs with Backblaze B2](https://www.suffix.be/blog/signed-urls-backblaze-b2/)
- [BigBinary: Cache with HMAC Auth in Cloudflare Workers](https://www.bigbinary.com/blog/how-to-cache-all-files-using-cloudflare-worker-along-with-hmac-authentication)
