# csrf-plus

Next-level protection against forged requests for Node.js applications.  
`csrf-plus` provides both stateful and stateless CSRF token strategies with optional masking and secure cookie handling.

## Features

- Lightweight CSRF protection middleware for Express
- Supports **stateful (server-side)** and **stateless (HMAC-signed)** tokens
- Optional token masking for additional security
- Configurable TTL, cookie options, and headers
- Origin and referer checks for defense-in-depth
- Easy integration with in-memory or Redis storage

## Installation

```bash
npm install csrf-plus
```

## Usage

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const createMiddleware = require('csrf-plus');

const app = express();
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const csrf = createCsrfPlus();

app.use(csrf.middleware);

app.get('/form', async (req, res) => {
    const token = await req.csrfPlus.token();
    res.send(`<form method="POST"><input type="hidden" name="_csrf" value="${token}"></form>`);
});

app.post('/submit', csrf.verify, (req, res) => {
    res.status(200).send('ok');
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

## Options

| Option           | Default                                                                            | Description                                                                |
| ---------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `cookieName`     | `'CSRF_PLUS_TOKEN'`                                                                | Name of the CSRF token cookie                                              |
| `cookieSidName`  | `'CSRF_PLUS_SID'`                                                                  | Name of the session ID cookie                                              |
| `headerName`     | `'x-csrf-plus'`                                                                    | Header to check for tokens in XHR requests                                 |
| `fieldName`      | `'_csrf'`                                                                          | Form body/query field name for submitted tokens                            |
| `store`          | `in-memory`                                                                        | Storage adapter implementing `get`, `set`, and `del` methods               |
| `ttl`            | `3600`                                                                             | Seconds to keep server-stored secrets                                      |
| `secretLen`      | `32`                                                                               | Secret length in bytes                                                     |
| `mask`           | `true`                                                                             | Whether to use masked synchronizer tokens                                  |
| `cookieOptions`  | `{ httpOnly: false, secure: true, sameSite: 'Lax', maxAge: 3600*1000, path: '/' }` | Options passed to `res.cookie()`                                           |
| `originCheck`    | `true`                                                                             | Whether to perform Origin/Referer defense-in-depth                         |
| `allowedMethods` | `['GET','HEAD','OPTIONS']`                                                         | HTTP methods that skip verification                                        |
| `stateless`      | `false`                                                                            | Use stateless HMAC tokens (no server store)                                |
| `statelessKey`   | `null`                                                                             | Secret used to sign/verify stateless tokens (required if `stateless=true`) |
| `statelessTTL`   | `3600000`                                                                          | TTL (ms) used when creating stateless tokens                               |

## Testing

```bash
npm install
npm test
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License - see [LICENSE](LICENSE) file.