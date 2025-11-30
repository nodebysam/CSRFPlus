/**
 * CSRF Plus
 * Next-level protection against forged requests
 * 
 * @author Sam Wilcox aka NodeBySam
 * @github https://github.com/nodebysam/CSRFPlus
 * 
 * CSRF Plus is released under the MIT license.
 * See the LICENSE file in the root of this
 * library's path.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Response, NextFunction } from 'express';
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const supertest = require('supertest');
const createMiddleware = require('../src/middleware');
const createMemoryStore = require('../src/storage/memory');

describe('middleware integration', () => {
    let app: any, agent: any;

    beforeEach(() => {
        app = express();
        app.use(cookieParser());
        app.use(bodyParser.urlencoded({ extended: true }));
        app.use(bodyParser.json());

        app.use((req: any, res: Response, next: NextFunction) => {
            req.session = { id: 'test-session' };
            next();
        });

        const csrf = createMiddleware({
            store: createMemoryStore(),
            cookieOptions: { secure: false, httpOnly: false, sameSite: 'Lax', maxAge: 3600 * 1000, path: '/' },
            originCheck: false
        });

        app.use(csrf.middleware);

        app.get('/form', async (req: any, res: any) => {
            const token = await req.csrfPlus.token();
            res.send(`<form method="POST"><input type="hidden" name="_csrf" value="${token}"></form>`);
        });

        app.post('/submit', csrf.verify, (req: any, res: any ) => {
            res.status(200).send('ok');
        });

        agent = supertest.agent(app);
    });

    it('GET /form sets token cookie and POST /submit with body passes', async () => {
        const getRes = await agent.get('/form').expect(200);
        const match = getRes.text.match(/name="_csrf" value="([^"]+)"/);
        expect(match).toBeTruthy();
        const token = match![1];

        await agent
            .post('/submit')
            .type('form')
            .send({ _csrf: token })
            .expect(200, 'ok');
    });

    it('POST /submit without token returns 403', async () => {
        await agent.post('/submit').expect(403);
    });

    it('POST /submit with header token passes (XHR style)', async () => {
        const getRes = await agent.get('/form').expect(200);
        const match = getRes.text.match(/name="_csrf" value="([^"]+)"/);
        const token = match![1];
        await agent
        .post('/submit')
        .set('x-csrf-plus', token)
        .expect(200, 'ok');
    });

    it('invalid token results in 403', async () => {
        await agent
        .post('/submit')
        .type('form')
        .send({ _csrf: 'not-a-valid-token' })
        .expect(403);
    });
});

describe('middleware stateless expiry', () => {
  it('rejects expired stateless token', async () => {
    const app = express();
    app.use(cookieParser());
    app.use(bodyParser.json());

    const key = 'test-stateless-key-xxx';
    const csrf = createMiddleware({
      stateless: true,
      statelessKey: key,
      statelessTTL: 10,
      cookieOptions: { secure: false, httpOnly: false, sameSite: 'Lax', maxAge: 3600 * 1000, path: '/' }
    });

    app.use(csrf.middleware);
    app.post('/submit', csrf.verify, (req: any, res: any) => res.send('ok'));

    const agent = supertest.agent(app);
    const { createStatelessToken } = require('../src/token/stateless');
    const expiredToken = createStatelessToken(-1000, key);

    await new Promise((r) => setTimeout(r, 10));

    await agent
      .post('/submit')
      .set('x-csrf-plus', expiredToken)
      .expect(403);
  });
});