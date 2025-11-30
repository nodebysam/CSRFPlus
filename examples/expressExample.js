// Example for Express
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { createCsrfPlus } = require('csrf-plus');

const app = express();
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const csrf = createCsrfPlus({
    cookieOptions: { secure: false, httpOnly: false, sameSite: 'Lax', maxAge: 3600 * 1000 },
    stateless: false
});

app.use(csrf.middleware);

app.get('/form', async (req, res) => {
    const token = await req.csrfPlus.token();
    res.send(`<form method="POST"><input type="hidden" name="_csrf" value=${token}"><input name="payload"><button>Send</button></form>`);
});

app.post('/submit', csrf.verify, (req, res) => {
    res.send('OK - CSRF verified');
});

app.listen(3000, () => console.log('listening on 3000'));