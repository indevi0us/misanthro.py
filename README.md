![Misanthropy Banner](assets/misanthro.py_banner.png)

**Misanthro.py** is a multi-threaded injection framework built to aggressively target HTTP headers, cookies, GET and POST parameters. It attacks all vectors without exception, using a customizable set of payloads delivered at high speed.

Designed for high-throughput injection workflows, **Misanthro.py** performs vector discovery from the DOM, supports authenticated sessions via cookie injection, and delivers payloads at scale. It is particularly suited for blind injection testing, especially blind XSS.

The tool does not attempt to interpret application responses. It is built to deliver, not to decide. Execution context, correlation, and exploit validation are expected to be handled externally, through platforms such as [BXSS Hunter](https://bxsshunter.com/) or similar platforms.

## Installation
```bash
git clone https://github.com/indevi0us/misanthro.py
cd misanthro.py/
pip install -r requirements.txt
```

## Arguments

| Argument             | Type      | Description                                                                 |
|----------------------|-----------|-----------------------------------------------------------------------------|
| `--url`              | `string`  | Target URL.                                                                |
| `--all`              | `flag`    | Runs automatic discovery, then attacks all discovered vectors.             |
| `--discovery`        | `flag`    | Performs vector discovery only (headers, cookies, GET, POST).              |
| `--headers`          | `string`  | Comma-separated list of HTTP headers to inject.                            |
| `--cookies`          | `string`  | Comma-separated list of cookie names to inject.                            |
| `--get`              | `string`  | Comma-separated list of GET parameters to inject.                          |
| `--post`             | `string`  | Comma-separated list of POST parameters to inject.                         |
| `--payloads`         | `string`  | Path to a YAML, JSON, or plaintext payload file. Default: `payloads.yaml`. |
| `--auth-cookies`     | `string`  | Authenticated session cookies in `"name=value; name2=value2"` format.      |
| `--threads`          | `int`     | Number of concurrent threads. Default: `10`.                               |
| `--rate-limit`       | `float`   | Delay in seconds between requests. Default: `0.0`.                         |
| `--help`             | `flag`    | Holds your hand and shows you the way out.                                 |


## Usage
Below are some examples demonstrating how to use **Misanthro.py** to test for blind injection vulnerabilities.

### Discovery Only
Parses the DOM and headers to list potential injection points. No requests are sent with payloads.
```bash
python3 misanthro.py --url https://target.com --discovery
```

### Full Auto
Discovers all injectable vectors (headers, cookies, GET, POST) and injects all payloads into every one of them.
```bash
python3 misanthro.py --url https://target.com --all --payloads payloads.yaml
```

### Targeting Specific Vectors
Skip discovery and attack only the explicitly specified vectors.
```bash
python3 misanthro.py --url https://target.com \
  --headers X-Forwarded-For,User-Agent \
  --cookies session_id \
  --get q,search \
  --post comment \
  --payloads payloads.yaml
```

### Authenticated Scan
Injects in authenticated requests using supplied cookies.
```bash
python3 misanthro.py --url https://target.com \
  --all \
  --auth-cookies "session=abc123; jwt=xyz456" \
  --payloads payloads.yaml
```

### Rate-Limited Testing
Injects payloads with a 0.5s delay between each request. Useful for avoiding rate-limiting or evading WAF heuristics.
```bash
python3 misanthro.py --url https://target.com \
  --all \
  --payloads payloads.yaml \
  --rate-limit 0.5
```
