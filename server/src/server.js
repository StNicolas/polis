import akismetLib from 'akismet';
import AWS from 'aws-sdk';
import badwords from 'badwords/object.js';
import bluebird from 'bluebird';
import http from 'http';
import httpProxy from 'http-proxy';
import async from 'async';
import FB from 'fb';
import { google } from 'googleapis';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import OAuth from 'oauth';
import replaceStream from 'replacestream';
import responseTime from 'response-time';
import request from 'request-promise';
import LruCache from 'lru-cache';
import timeout from 'connect-timeout';
import _ from 'underscore';
import pg from 'pg';
import { encode } from 'html-entities';
import { METRICS_IN_RAM, addInRamMetric, MPromise } from './utils/metered.js';
import CreateUser from './auth/create-user.js';
import Password from './auth/password.js';
import dbPgQuery, {
  query as pgQuery,
  query_readOnly as pgQuery_readOnly,
  queryP as pgQueryP,
  queryP_metered_readOnly as pgQueryP_metered_readOnly,
  queryP_readOnly as pgQueryP_readOnly,
  queryP_readOnly_wRetryIfEmpty as pgQueryP_readOnly_wRetryIfEmpty
} from './db/pg-query.js';
import Config from './config.js';
import fail from './utils/fail.js';
import { getPca, fetchAndCacheLatestPcaData } from './utils/pca.js';
import { getZinvite, getZinvites, getZidForRid } from './utils/zinvite.js';
import { handle_GET_reportExport } from './routes/export.js';
AWS.config.update({ region: Config.awsRegion });
const { Promise: BluebirdPromise } = bluebird;
const devMode = Config.isDevMode;
const s3Client = new AWS.S3({ apiVersion: '2006-03-01' });
const escapeLiteral = pg.Client.prototype.escapeLiteral;
const doSendVerification = CreateUser.doSendVerification;
const generateAndRegisterZinvite = CreateUser.generateAndRegisterZinvite;
const generateToken = Password.generateToken;
const generateTokenP = Password.generateTokenP;
import { checkPassword, generateHashedPassword } from './auth/password.js';
import cookies from './utils/cookies.js';
const COOKIES = cookies.COOKIES;
const COOKIES_TO_CLEAR = cookies.COOKIES_TO_CLEAR;
import constants from './utils/constants.js';
const DEFAULTS = constants.DEFAULTS;
import User from './user.js';
import Conversation from './conversation.js';
import Session from './session.js';
import Comment from './comment.js';
import Utils from './utils/common.js';
import SQL from './db/sql.js';
import logger from './utils/logger.js';
import emailSenders from './email/senders.js';
const sendTextEmail = emailSenders.sendTextEmail;
const sendTextEmailWithBackupOnly = emailSenders.sendTextEmailWithBackupOnly;
const _resolveWith = (x) => {
  return Promise.resolve(x);
};
if (devMode) {
  BluebirdPromise.longStackTraces();
}
BluebirdPromise.onPossiblyUnhandledRejection((err) => {
  logger.error('onPossiblyUnhandledRejection', err);
});
const adminEmails = Config.adminEmails ? JSON.parse(Config.adminEmails) : [];
const polisDevs = Config.adminUIDs ? JSON.parse(Config.adminUIDs) : [];
function isPolisDev(uid) {
  return polisDevs.indexOf(uid) >= 0;
}
const polisFromAddress = Config.polisFromAddress;
const serverUrl = Config.getServerUrl();
const akismet = akismetLib.client({
  blog: serverUrl,
  apiKey: Config.akismetAntispamApiKey
});
akismet.verifyKey((_err, verified) => {
  if (verified) {
    logger.debug('Akismet: API key successfully verified.');
  } else {
    logger.debug('Akismet: Unable to verify API key.');
  }
});
function isSpam(o) {
  return new MPromise('isSpam', (resolve, reject) => {
    akismet.checkSpam(o, (err, spam) => {
      if (err) {
        reject(err);
      } else {
        resolve(spam);
      }
    });
  });
}
let _INFO;
function DD(f) {
  this.m = {};
  this.f = f;
}
function DA(f) {
  this.m = [];
  this.f = f;
}
DD.prototype.g = DA.prototype.g = function (k) {
  if (this.m.hasOwnProperty(k)) {
    return this.m[k];
  }
  const v = this.f(k);
  this.m[k] = v;
  return v;
};
DD.prototype.s = DA.prototype.s = function (k, v) {
  this.m[k] = v;
};
const domainOverride = Config.domainOverride;
function haltOnTimeout(req, res, next) {
  if (req.timedout) {
    fail(res, 500, 'polis_err_timeout_misc');
  } else {
    next();
  }
}
function ifDefinedSet(name, source, dest) {
  if (!_.isUndefined(source[name])) {
    dest[name] = source[name];
  }
}
const sql_votes_latest_unique = SQL.sql_votes_latest_unique;
const sql_conversations = SQL.sql_conversations;
const sql_participant_metadata_answers = SQL.sql_participant_metadata_answers;
const sql_participants_extended = SQL.sql_participants_extended;
const sql_reports = SQL.sql_reports;
const sql_users = SQL.sql_users;
const encrypt = Session.encrypt;
const _decrypt = Session.decrypt;
const makeSessionToken = Session.makeSessionToken;
const getUserInfoForSessionToken = Session.getUserInfoForSessionToken;
const startSession = Session.startSession;
const endSession = Session.endSession;
const setupPwReset = Session.setupPwReset;
const getUidForPwResetToken = Session.getUidForPwResetToken;
const clearPwResetToken = Session.clearPwResetToken;
function hasAuthToken(req) {
  return !!req.cookies[COOKIES.TOKEN];
}
function getUidForApiKey(apikey) {
  return pgQueryP_readOnly_wRetryIfEmpty('select uid from apikeysndvweifu WHERE apikey = ($1);', [apikey]);
}
function doApiKeyBasicAuth(assigner, header, isOptional, req, res, next) {
  const token = header.split(/\s+/).pop() || '';
  const auth = Buffer.from(token, 'base64').toString();
  const parts = auth.split(/:/);
  const username = parts[0];
  const apikey = username;
  return doApiKeyAuth(assigner, apikey, isOptional, req, res, next);
}
function doApiKeyAuth(assigner, apikey, _isOptional, req, res, next) {
  getUidForApiKey(apikey)
    .then((rows) => {
      if (!rows || !rows.length) {
        res.status(403);
        next('polis_err_auth_no_such_api_token');
        return;
      }
      assigner(req, 'uid', Number(rows[0].uid));
      next();
    })
    .catch((err) => {
      res.status(403);
      logger.error('polis_err_auth_no_such_api_token2', err);
      next('polis_err_auth_no_such_api_token2');
    });
}
const createDummyUser = User.createDummyUser;
const getConversationInfo = Conversation.getConversationInfo;
const getConversationInfoByConversationId = Conversation.getConversationInfoByConversationId;
const isXidWhitelisted = Conversation.isXidWhitelisted;
const getXidRecordByXidOwnerId = User.getXidRecordByXidOwnerId;
function doXidApiKeyAuth(assigner, apikey, xid, isOptional, req, res, next) {
  getUidForApiKey(apikey)
    .then(
      (rows) => {
        if (!rows || !rows.length) {
          res.status(403);
          next('polis_err_auth_no_such_api_token4');
          return;
        }
        const uidForApiKey = Number(rows[0].uid);
        return getXidRecordByXidOwnerId(
          xid,
          uidForApiKey,
          void 0,
          req.body.x_profile_image_url || req?.query?.x_profile_image_url,
          req.body.x_name || req?.query?.x_name || null,
          req.body.x_email || req?.query?.x_email || null,
          !!req.body.agid || !!req?.query?.agid || null
        ).then((rows) => {
          if (!rows || !rows.length) {
            if (isOptional) {
              return next();
            }
            res.status(403);
            next('polis_err_auth_no_such_xid_for_this_apikey_1');
            return;
          }
          const uidForCurrentUser = Number(rows[0].uid);
          assigner(req, 'uid', uidForCurrentUser);
          assigner(req, 'xid', xid);
          assigner(req, 'owner_uid', uidForApiKey);
          assigner(req, 'org_id', uidForApiKey);
          next();
        });
      },
      (err) => {
        res.status(403);
        logger.error('polis_err_auth_no_such_api_token3', err);
        next('polis_err_auth_no_such_api_token3');
      }
    )
    .catch((err) => {
      res.status(403);
      logger.error('polis_err_auth_misc_23423', err);
      next('polis_err_auth_misc_23423');
    });
}
function doHeaderAuth(assigner, _isOptional, req, res, next) {
  let token = '';
  if (req?.headers) token = req?.headers?.['x-polis'];
  getUserInfoForSessionToken(token, res, (err, uid) => {
    if (err) {
      res.status(403);
      next('polis_err_auth_no_such_token');
      return;
    }
    if (req.body.uid && req.body.uid !== uid) {
      res.status(401);
      next('polis_err_auth_mismatch_uid');
      return;
    }
    assigner(req, 'uid', Number(uid));
    next();
  });
}
String.prototype.hashCode = function () {
  let hash = 0;
  let i;
  let character;
  if (this.length === 0) {
    return hash;
  }
  for (i = 0; i < this.length; i++) {
    character = this.charCodeAt(i);
    hash = (hash << 5) - hash + character;
    hash = hash & hash;
  }
  return hash;
};
function initializePolisHelpers() {
  const polisTypes = Utils.polisTypes;
  const setCookie = cookies.setCookie;
  const setParentReferrerCookie = cookies.setParentReferrerCookie;
  const setParentUrlCookie = cookies.setParentUrlCookie;
  const setPermanentCookie = cookies.setPermanentCookie;
  const setCookieTestCookie = cookies.setCookieTestCookie;
  const addCookies = cookies.addCookies;
  const getPermanentCookieAndEnsureItIsSet = cookies.getPermanentCookieAndEnsureItIsSet;
  const pidCache = User.pidCache;
  const getPid = User.getPid;
  const getPidPromise = User.getPidPromise;
  const getPidForParticipant = User.getPidForParticipant;
  function recordPermanentCookieZidJoin(permanentCookieToken, zid) {
    function doInsert() {
      return pgQueryP('insert into permanentCookieZidJoins (cookie, zid) values ($1, $2);', [
        permanentCookieToken,
        zid
      ]);
    }
    return pgQueryP('select zid from permanentCookieZidJoins where cookie = ($1) and zid = ($2);', [
      permanentCookieToken,
      zid
    ]).then(
      (rows) => {
        if (rows?.length) {
        } else {
          return doInsert();
        }
      },
      (err) => {
        logger.error('error in recordPermanentCookieZidJoin', err);
        return doInsert();
      }
    );
  }
  const detectLanguage = Comment.detectLanguage;
  if (Config.backfillCommentLangDetection) {
    pgQueryP('select tid, txt, zid from comments where lang is null;', []).then((comments) => {
      let i = 0;
      function doNext() {
        if (i < comments.length) {
          const c = comments[i];
          i += 1;
          detectLanguage(c.txt).then((x) => {
            const firstResult = x[0];
            logger.debug(`backfill ${firstResult.language}\t\t${c.txt}`);
            pgQueryP('update comments set lang = ($1), lang_confidence = ($2) where zid = ($3) and tid = ($4)', [
              firstResult.language,
              firstResult.confidence,
              c.zid,
              c.tid
            ]).then(() => {
              doNext();
            });
          });
        }
      }
      doNext();
    });
  }
  function doVotesPost(_uid, pid, conv, tid, voteType, weight) {
    const zid = conv?.zid;
    weight = weight || 0;
    const weight_x_32767 = Math.trunc(weight * 32767);
    return new Promise((resolve, reject) => {
      const query =
        'INSERT INTO votes (pid, zid, tid, vote, weight_x_32767, created) VALUES ($1, $2, $3, $4, $5, default) RETURNING *;';
      const params = [pid, zid, tid, voteType, weight_x_32767];
      pgQuery(query, params, (err, result) => {
        if (err) {
          if (isDuplicateKey(err)) {
            reject('polis_err_vote_duplicate');
          } else {
            logger.error('polis_err_vote_other', err);
            reject('polis_err_vote_other');
          }
          return;
        }
        const vote = result.rows[0];
        resolve({
          conv: conv,
          vote: vote
        });
      });
    });
  }
  function votesPost(uid, pid, zid, tid, xid, voteType, weight) {
    return pgQueryP_readOnly('select * from conversations where zid = ($1);', [zid])
      .then((rows) => {
        if (!rows || !rows.length) {
          throw 'polis_err_unknown_conversation';
        }
        const conv = rows[0];
        if (!conv.is_active) {
          throw 'polis_err_conversation_is_closed';
        }
        if (conv.use_xid_whitelist) {
          return isXidWhitelisted(conv.owner, xid).then((is_whitelisted) => {
            if (is_whitelisted) {
              return conv;
            }
            throw 'polis_err_xid_not_whitelisted';
          });
        }
        return conv;
      })
      .then((conv) => doVotesPost(uid, pid, conv, tid, voteType, weight));
  }
  function getVotesForSingleParticipant(p) {
    if (_.isUndefined(p.pid)) {
      return Promise.resolve([]);
    }
    return votesGet(p);
  }
  function votesGet(p) {
    return new MPromise('votesGet', (resolve, reject) => {
      let q = sql_votes_latest_unique
        .select(sql_votes_latest_unique.star())
        .where(sql_votes_latest_unique.zid.equals(p.zid));
      if (!_.isUndefined(p.pid)) {
        q = q.where(sql_votes_latest_unique.pid.equals(p.pid));
      }
      if (!_.isUndefined(p.tid)) {
        q = q.where(sql_votes_latest_unique.tid.equals(p.tid));
      }
      pgQuery_readOnly(q.toString(), (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results.rows);
        }
      });
    });
  }
  function writeDefaultHead(_req, res, next) {
    res.set({
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    next();
  }
  function redirectIfNotHttps(req, res, next) {
    if (devMode || req.path === '/api/v3/testConnection') {
      return next();
    }
    const isHttps = req.headers['x-forwarded-proto'] === 'https';
    if (!isHttps) {
      logger.debug('redirecting to https', { headers: req.headers });
      if (req.method === 'GET') {
        res.writeHead(302, {
          Location: `https://${req.headers.host}${req.url}`
        });
        return res.end();
      }
      res.status(400).send('Please use HTTPS when submitting data.');
    }
    return next();
  }
  function doXidConversationIdAuth(assigner, xid, conversation_id, isOptional, req, res, onDone) {
    return getConversationInfoByConversationId(conversation_id)
      .then((conv) => {
        return getXidRecordByXidOwnerId(
          xid,
          conv.org_id,
          conv.zid,
          req.body.x_profile_image_url || req?.query?.x_profile_image_url,
          req.body.x_name || req?.query?.x_name || null,
          req.body.x_email || req?.query?.x_email || null,
          !!req.body.agid || !!req?.query?.agid || null
        ).then((rows) => {
          if (!rows || !rows.length) {
            if (isOptional) {
              return onDone();
            }
            res.status(403);
            onDone('polis_err_auth_no_such_xid_for_this_apikey_11');
            return;
          }
          const uidForCurrentUser = Number(rows[0].uid);
          assigner(req, 'uid', uidForCurrentUser);
          onDone();
        });
      })
      .catch((err) => {
        logger.error('doXidConversationIdAuth error', err);
        onDone(err);
      });
  }
  function _auth(assigner, isOptional) {
    function getKey(req, key) {
      return req.body[key] || req?.headers?.[key] || req?.query?.[key];
    }
    function doAuth(req, res) {
      const token = req.cookies[COOKIES.TOKEN];
      const xPolisToken = req?.headers?.['x-polis'];
      return new Promise((resolve, reject) => {
        function onDone(err) {
          if (err) {
            reject(err);
          }
          if ((!req.p || !req.p.uid) && !isOptional) {
            reject('polis_err_mandatory_auth_unsuccessful');
          }
          resolve(req.p?.uid);
        }
        if (xPolisToken) {
          logger.info('authtype: doHeaderAuth');
          doHeaderAuth(assigner, isOptional, req, res, onDone);
        } else if (getKey(req, 'polisApiKey') && getKey(req, 'ownerXid')) {
          doXidApiKeyAuth(assigner, getKey(req, 'polisApiKey'), getKey(req, 'ownerXid'), isOptional, req, res, onDone);
        } else if (getKey(req, 'polisApiKey') && getKey(req, 'xid')) {
          doXidApiKeyAuth(assigner, getKey(req, 'polisApiKey'), getKey(req, 'xid'), isOptional, req, res, onDone);
        } else if (getKey(req, 'xid') && getKey(req, 'conversation_id')) {
          doXidConversationIdAuth(
            assigner,
            getKey(req, 'xid'),
            getKey(req, 'conversation_id'),
            isOptional,
            req,
            res,
            onDone
          );
        } else if (req?.headers?.['x-sandstorm-app-polis-apikey']) {
          doApiKeyAuth(assigner, req?.headers?.['x-sandstorm-app-polis-apikey'], isOptional, req, res, onDone);
        } else if (req.body.polisApiKey) {
          doApiKeyAuth(assigner, getKey(req, 'polisApiKey'), isOptional, req, res, onDone);
        } else if (token) {
          doCookieAuth(assigner, isOptional, req, res, onDone);
        } else if (req?.headers?.authorization) {
          doApiKeyBasicAuth(assigner, req.headers.authorization, isOptional, req, res, onDone);
        } else if (req.body.agid) {
          createDummyUser()
            .then(
              (uid) => {
                const shouldAddCookies = _.isUndefined(req.body.xid);
                if (!shouldAddCookies) {
                  req.p = req.p || {};
                  req.p.uid = uid;
                  return onDone();
                }
                return startSessionAndAddCookies(req, res, uid).then(
                  () => {
                    req.p = req.p || {};
                    req.p.uid = uid;
                    onDone();
                  },
                  (err) => {
                    res.status(500);
                    logger.error('polis_err_auth_token_error_2343', err);
                    onDone('polis_err_auth_token_error_2343');
                  }
                );
              },
              (err) => {
                res.status(500);
                logger.error('polis_err_auth_token_error_1241', err);
                onDone('polis_err_auth_token_error_1241');
              }
            )
            .catch((err) => {
              res.status(500);
              logger.error('polis_err_auth_token_error_5345', err);
              onDone('polis_err_auth_token_error_5345');
            });
        } else if (isOptional) {
          onDone();
        } else {
          res.status(401);
          onDone('polis_err_auth_token_not_supplied');
        }
      });
    }
    return (req, res, next) => {
      doAuth(req, res)
        .then(() => {
          return next();
        })
        .catch((err) => {
          res.status(500);
          logger.error('polis_err_auth_error_432', err);
          next(err || 'polis_err_auth_error_432');
        });
    };
  }
  function authOptional(assigner) {
    return _auth(assigner, true);
  }
  function auth(assigner) {
    return _auth(assigner, false);
  }
  function enableAgid(req, _res, next) {
    req.body.agid = 1;
    next();
  }
  const whitelistedCrossDomainRoutes = [/^\/api\/v[0-9]+\/launchPrep/, /^\/api\/v[0-9]+\/setFirstCookie/];
  const whitelistedDomains = [
    Config.getServerHostname(),
    ...Config.whitelistItems,
    'localhost:5000',
    'localhost:5001',
    'localhost:5010',
    'facebook.com',
    'api.twitter.com',
    ''
  ];
  function hasWhitelistMatches(host) {
    let hostWithoutProtocol = host;
    if (host.startsWith('http://')) {
      hostWithoutProtocol = host.slice(7);
    } else if (host.startsWith('https://')) {
      hostWithoutProtocol = host.slice(8);
    }
    for (let i = 0; i < whitelistedDomains.length; i++) {
      const w = whitelistedDomains[i];
      if (hostWithoutProtocol.endsWith(w || '')) {
        if (hostWithoutProtocol === w) {
          return true;
        }
        if (hostWithoutProtocol[hostWithoutProtocol.length - ((w || '').length + 1)] === '.') {
          return true;
        }
      }
    }
    return false;
  }
  function addCorsHeader(req, res, next) {
    let host = '';
    if (domainOverride) {
      host = `${req.protocol}://${domainOverride}`;
    } else {
      host = req.get('Origin') || req.get('Referer') || '';
    }
    host = host.replace(/#.*$/, '');
    const result = /^[^\/]*\/\/[^\/]*/.exec(host);
    if (result?.[0]) {
      host = result[0];
    }
    const routeIsWhitelistedForAnyDomain = _.some(whitelistedCrossDomainRoutes, (regex) => regex.test(req.path));
    if (!domainOverride && !hasWhitelistMatches(host) && !routeIsWhitelistedForAnyDomain) {
      logger.info('not whitelisted', { headers: req.headers, path: req.path });
      return next(`unauthorized domain: ${host}`);
    }
    if (host === '') {
    } else {
      res.header('Access-Control-Allow-Origin', host);
      res.header(
        'Access-Control-Allow-Headers',
        'Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With'
      );
      res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Credentials', true);
    }
    return next();
  }
  const strToHex = Utils.strToHex;
  const hexToStr = Utils.hexToStr;
  function handle_GET_launchPrep(req, res) {
    if (!req.cookies[COOKIES.PERMANENT_COOKIE]) {
      setPermanentCookie(req, res, makeSessionToken());
    }
    setCookieTestCookie(req, res);
    setCookie(req, res, 'top', 'ok', {
      httpOnly: false
    });
    const dest = hexToStr(req.p.dest);
    const url = new URL(dest);
    res.redirect(url.pathname + url.search + url.hash);
  }
  function handle_GET_tryCookie(req, res) {
    if (!req.cookies[COOKIES.TRY_COOKIE]) {
      setCookie(req, res, COOKIES.TRY_COOKIE, 'ok', {
        httpOnly: false
      });
    }
    res.status(200).json({});
  }
  fetchAndCacheLatestPcaData;
  function redirectIfHasZidButNoConversationId(req, res, next) {
    if (req.body.zid && !req.body.conversation_id) {
      logger.info('redirecting old zid user to about page');
      const path = '/about';
      const protocol = req.headers['x-forwarded-proto'] || 'http';
      res.writeHead(302, {
        Location: `${protocol}://${req?.headers?.host}${path}`
      });
      return res.end();
    }
    return next();
  }
  function handle_GET_math_pca(_req, res) {
    res.status(304).end();
  }
  const pcaResultsExistForZid = {};
  function handle_GET_math_pca2(req, res) {
    const zid = req.p.zid;
    let math_tick = req.p.math_tick;
    const ifNoneMatch = req.p.ifNoneMatch;
    if (ifNoneMatch) {
      if (!_.isUndefined(math_tick)) {
        return fail(res, 400, 'Expected either math_tick param or If-Not-Match header, but not both.');
      }
      if (ifNoneMatch.includes('*')) {
        math_tick = 0;
      } else {
        const entries = ifNoneMatch.split(/ *, */).map((x) => {
          return Number(
            x
              .replace(/^[wW]\//, '')
              .replace(/^"/, '')
              .replace(/"$/, '')
          );
        });
        math_tick = _.min(entries);
      }
    } else if (_.isUndefined(math_tick)) {
      math_tick = -1;
    }
    function finishWith304or404() {
      if (pcaResultsExistForZid[zid]) {
        res.status(304).end();
      } else {
        res.status(304).end();
      }
    }
    getPca(zid, math_tick)
      .then((data) => {
        if (data) {
          res.set({
            'Content-Type': 'application/json',
            'Content-Encoding': 'gzip',
            Etag: `"${data.asPOJO.math_tick}"`
          });
          res.send(data.asBufferOfGzippedJson);
        } else {
          if (_.isUndefined(pcaResultsExistForZid[zid])) {
            return getPca(zid, -1).then((data) => {
              const exists = !!data;
              pcaResultsExistForZid[zid] = exists;
              finishWith304or404();
            });
          }
          finishWith304or404();
        }
      })
      .catch((err) => {
        fail(res, 500, err);
      });
  }
  function handle_POST_math_update(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const math_env = Config.mathEnv;
    const math_update_type = req.p.math_update_type;
    isModerator(zid, uid).then((hasPermission) => {
      if (!hasPermission) {
        return fail(res, 500, 'handle_POST_math_update_permission');
      }
      return pgQueryP(
        "insert into worker_tasks (task_type, task_data, task_bucket, math_env) values ('update_math', $1, $2, $3);",
        [
          JSON.stringify({
            zid: zid,
            math_update_type: math_update_type
          }),
          zid,
          math_env
        ]
      )
        .then(() => {
          res.status(200).json({});
        })
        .catch((err) => {
          return fail(res, 500, 'polis_err_POST_math_update', err);
        });
    });
  }
  function handle_GET_math_correlationMatrix(req, res) {
    const rid = req.p.rid;
    const math_env = Config.mathEnv;
    const math_tick = req.p.math_tick;
    function finishAsPending() {
      res.status(202).json({
        status: 'pending'
      });
    }
    function hasCommentSelections() {
      return pgQueryP('select * from report_comment_selections where rid = ($1) and selection = 1;', [rid]).then(
        (rows) => {
          return rows.length > 0;
        }
      );
    }
    const requestExistsPromise = pgQueryP(
      "select * from worker_tasks where task_type = 'generate_report_data' and math_env=($2) " +
        'and task_bucket = ($1) ' +
        "and (task_data->>'math_tick')::int >= ($3) " +
        'and finished_time is NULL;',
      [rid, math_env, math_tick]
    );
    const resultExistsPromise = pgQueryP(
      'select * from math_report_correlationmatrix where rid = ($1) and math_env = ($2) and math_tick >= ($3);',
      [rid, math_env, math_tick]
    );
    Promise.all([resultExistsPromise, getZidForRid(rid)])
      .then((a) => {
        const rows = a[0];
        const zid = a[1];
        if (!rows || !rows.length) {
          return requestExistsPromise.then((requests_rows) => {
            const shouldAddTask = !requests_rows || !requests_rows.length;
            if (shouldAddTask) {
              return hasCommentSelections().then((hasSelections) => {
                if (!hasSelections) {
                  return res.status(202).json({
                    status: 'polis_report_needs_comment_selection'
                  });
                }
                return pgQueryP(
                  "insert into worker_tasks (task_type, task_data, task_bucket, math_env) values ('generate_report_data', $1, $2, $3);",
                  [
                    JSON.stringify({
                      rid: rid,
                      zid: zid,
                      math_tick: math_tick
                    }),
                    rid,
                    math_env
                  ]
                ).then(finishAsPending);
              });
            }
            finishAsPending();
          });
        }
        res.json(rows[0].data);
      })
      .catch((err) => {
        return fail(res, 500, 'polis_err_GET_math_correlationMatrix', err);
      });
  }
  function doAddDataExportTask(math_env, email, zid, atDate, format, task_bucket) {
    return pgQueryP(
      "insert into worker_tasks (math_env, task_data, task_type, task_bucket) values ($1, $2, 'generate_export_data', $3);",
      [
        math_env,
        {
          email: email,
          zid: zid,
          'at-date': atDate,
          format: format
        },
        task_bucket
      ]
    );
  }
  if (Config.runPeriodicExportTests && !devMode && Config.mathEnv === 'preprod') {
    const runExportTest = () => {
      const math_env = 'prod';
      const email = Config.adminEmailDataExportTest;
      const zid = 12480;
      const atDate = Date.now();
      const format = 'csv';
      const task_bucket = Math.abs((Math.random() * 999999999999) >> 0);
      doAddDataExportTask(math_env, email, zid, atDate, format, task_bucket).then(() => {
        setTimeout(
          () => {
            pgQueryP("select * from worker_tasks where task_type = 'generate_export_data' and task_bucket = ($1);", [
              task_bucket
            ]).then((rows) => {
              const ok = rows?.length;
              let newOk;
              if (ok) {
                newOk = rows[0].finished_time > 0;
              }
              if (ok && newOk) {
                logger.info('runExportTest success');
              } else {
                logger.error('runExportTest failed');
                emailBadProblemTime("Math export didn't finish.");
              }
            });
          },
          10 * 60 * 1000
        );
      });
    };
    setInterval(runExportTest, 6 * 60 * 60 * 1000);
  }
  function handle_GET_dataExport(req, res) {
    getUserInfoForUid2(req.p.uid)
      .then((user) => {
        return doAddDataExportTask(
          Config.mathEnv,
          user.email,
          req.p.zid,
          req.p.unixTimestamp * 1000,
          req.p.format,
          Math.abs((Math.random() * 999999999999) >> 0)
        )
          .then(() => {
            res.json({});
          })
          .catch((err) => {
            fail(res, 500, 'polis_err_data_export123', err);
          });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_data_export123b', err);
      });
  }
  function handle_GET_dataExport_results(req, res) {
    const url = s3Client.getSignedUrl('getObject', {
      Bucket: 'polis-datadump',
      Key: `${Config.mathEnv}/${req.p.filename}`,
      Expires: 60 * 60 * 24 * 7
    });
    res.redirect(url);
  }
  function getBidIndexToPidMapping(zid, math_tick) {
    math_tick = math_tick || -1;
    return pgQueryP_readOnly('select * from math_bidtopid where zid = ($1) and math_env = ($2);', [
      zid,
      Config.mathEnv
    ]).then((rows) => {
      if (!rows || !rows.length) {
        return new Error('polis_err_get_pca_results_missing');
      }
      if (rows[0].data.math_tick <= math_tick) {
        return new Error('polis_err_get_pca_results_not_new');
      }
      return rows[0].data;
    });
  }
  function handle_GET_bidToPid(req, res) {
    const zid = req.p.zid;
    const math_tick = req.p.math_tick;
    getBidIndexToPidMapping(zid, math_tick).then(
      (doc) => {
        const b2p = doc.bidToPid;
        res.json({
          bidToPid: b2p
        });
      },
      (_err) => {
        res.status(304).end();
      }
    );
  }
  function getXids(zid) {
    return new MPromise('getXids', (resolve, reject) => {
      pgQuery_readOnly(
        'select pid, xid from xids inner join ' +
          '(select * from participants where zid = ($1)) as p on xids.uid = p.uid ' +
          ' where owner in (select org_id from conversations where zid = ($1));',
        [zid],
        (err, result) => {
          if (err) {
            reject('polis_err_fetching_xids');
            return;
          }
          resolve(result.rows);
        }
      );
    });
  }
  function handle_GET_xids(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    isOwner(zid, uid).then(
      (owner) => {
        if (owner) {
          getXids(zid).then(
            (xids) => {
              res.status(200).json(xids);
            },
            (err) => {
              fail(res, 500, 'polis_err_get_xids', err);
            }
          );
        } else {
          fail(res, 403, 'polis_err_get_xids_not_authorized');
        }
      },
      (err) => {
        fail(res, 500, 'polis_err_get_xids', err);
      }
    );
  }
  function handle_POST_xidWhitelist(req, res) {
    const xid_whitelist = req.p.xid_whitelist;
    const len = xid_whitelist.length;
    const owner = req.p.uid;
    const entries = [];
    try {
      for (let i = 0; i < len; i++) {
        entries.push(`(${escapeLiteral(xid_whitelist[i])},${owner})`);
      }
    } catch (err) {
      return fail(res, 400, 'polis_err_bad_xid', err);
    }
    pgQueryP(`insert into xid_whitelist (xid, owner) values ${entries.join(',')} on conflict do nothing;`, [])
      .then((_result) => {
        res.status(200).json({});
      })
      .catch((err) => {
        return fail(res, 500, 'polis_err_POST_xidWhitelist', err);
      });
  }
  function getBidsForPids(zid, math_tick, pids) {
    const dataPromise = getBidIndexToPidMapping(zid, math_tick);
    const mathResultsPromise = getPca(zid, math_tick);
    return Promise.all([dataPromise, mathResultsPromise]).then((items) => {
      const b2p = items[0].bidToPid || [];
      const mathResults = items[1].asPOJO;
      function findBidForPid(pid) {
        let yourBidi = -1;
        for (let bidi = 0; bidi < b2p.length; bidi++) {
          const pids = b2p[bidi];
          if (pids.indexOf(pid) !== -1) {
            yourBidi = bidi;
            break;
          }
        }
        let yourBid = indexToBid[yourBidi];
        if (yourBidi >= 0 && _.isUndefined(yourBid)) {
          logger.error('polis_err_math_index_mapping_mismatch', { pid, b2p });
          yourBid = -1;
        }
        return yourBid;
      }
      const indexToBid = mathResults['base-clusters'].id;
      const bids = pids.map(findBidForPid);
      const pidToBid = _.object(pids, bids);
      return pidToBid;
    });
  }
  function handle_GET_bid(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    const math_tick = req.p.math_tick;
    const dataPromise = getBidIndexToPidMapping(zid, math_tick);
    const pidPromise = getPidPromise(zid, uid);
    const mathResultsPromise = getPca(zid, math_tick);
    Promise.all([dataPromise, pidPromise, mathResultsPromise])
      .then(
        (items) => {
          const b2p = items[0].bidToPid || [];
          const pid = items[1];
          const mathResults = items[2].asPOJO;
          if (pid < 0) {
            fail(res, 500, 'polis_err_get_bid_bad_pid');
            return;
          }
          const indexToBid = mathResults['base-clusters'].id;
          let yourBidi = -1;
          for (let bidi = 0; bidi < b2p.length; bidi++) {
            const pids = b2p[bidi];
            if (pids.indexOf(pid) !== -1) {
              yourBidi = bidi;
              break;
            }
          }
          let yourBid = indexToBid[yourBidi];
          if (yourBidi >= 0 && _.isUndefined(yourBid)) {
            logger.error('polis_err_math_index_mapping_mismatch', { pid, b2p });
            yourBid = -1;
          }
          res.json({
            bid: yourBid
          });
        },
        (_err) => {
          res.status(304).end();
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_get_bid_misc', err);
      });
  }
  function handle_POST_auth_password(req, res) {
    const pwresettoken = req.p.pwresettoken;
    const newPassword = req.p.newPassword;
    getUidForPwResetToken(pwresettoken, (err, userParams) => {
      if (err) {
        fail(res, 500, "Password Reset failed. Couldn't find matching pwresettoken.", err);
        return;
      }
      const uid = Number(userParams.uid);
      generateHashedPassword(newPassword, (_err, hashedPassword) =>
        pgQueryP(
          'insert into jianiuevyew (uid, pwhash) values ' +
            '($1, $2) on conflict (uid) ' +
            'do update set pwhash = excluded.pwhash;',
          [uid, hashedPassword]
        ).then(
          (_rows) => {
            res.status(200).json('Password reset successful.');
            clearPwResetToken(pwresettoken, (err) => {
              if (err) {
                logger.error('polis_err_auth_pwresettoken_clear_fail', err);
              }
            });
          },
          (err) => {
            fail(res, 500, "Couldn't reset password.", err);
          }
        )
      );
    });
  }
  const getServerNameWithProtocol = Config.getServerNameWithProtocol;
  function handle_POST_auth_pwresettoken(req, res) {
    const email = req.p.email;
    const server = getServerNameWithProtocol(req);
    clearCookies(req, res);
    function finish() {
      res.status(200).json('Password reset email sent, please check your email.');
    }
    getUidByEmail(email).then(
      (uid) => {
        setupPwReset(uid, (_err, pwresettoken) => {
          sendPasswordResetEmail(uid, pwresettoken, server, (err) => {
            if (err) {
              fail(res, 500, "Error: Couldn't send password reset email.", err);
              return;
            }
            finish();
          });
        });
      },
      () => {
        sendPasswordResetEmailFailure(email, server);
        finish();
      }
    );
  }
  function sendPasswordResetEmailFailure(email, server) {
    const body = `We were unable to find a pol.is account registered with the email address: ${email}

You may have used another email address to create your account.

If you need to create a new account, you can do that here ${server}/home

Feel free to reply to this email if you need help.`;
    return sendTextEmail(polisFromAddress, email, 'Password Reset Failed', body);
  }
  function getUidByEmail(email) {
    email = email.toLowerCase();
    return pgQueryP_readOnly('SELECT uid FROM users where LOWER(email) = ($1);', [email]).then((rows) => {
      if (!rows || !rows.length) {
        throw new Error('polis_err_no_user_matching_email');
      }
      return rows[0].uid;
    });
  }
  function clearCookie(req, res, cookieName) {
    res?.clearCookie?.(cookieName, {
      path: '/',
      domain: cookies.cookieDomain(req)
    });
  }
  function clearCookies(req, res) {
    let cookieName;
    for (cookieName in req.cookies) {
      if (COOKIES_TO_CLEAR[cookieName]) {
        res?.clearCookie?.(cookieName, {
          path: '/',
          domain: cookies.cookieDomain(req)
        });
      }
    }
    logger.info(`after clear res set-cookie: ${JSON.stringify(res?._headers?.['set-cookie'])}`);
  }
  function doCookieAuth(assigner, isOptional, req, res, next) {
    const token = req.cookies[COOKIES.TOKEN];
    getUserInfoForSessionToken(token, res, (err, uid) => {
      if (err) {
        clearCookies(req, res);
        if (isOptional) {
          next();
        } else {
          res.status(403);
          next('polis_err_auth_no_such_token');
        }
        return;
      }
      if (req.body.uid && req.body.uid !== uid) {
        res.status(401);
        next('polis_err_auth_mismatch_uid');
        return;
      }
      assigner(req, 'uid', Number(uid));
      next();
    });
  }
  function handle_POST_auth_deregister(req, res) {
    req.p = req.p || {};
    const token = req.cookies[COOKIES.TOKEN];
    clearCookies(req, res);
    function finish() {
      if (!req.p.showPage) {
        res.status(200).end();
      }
    }
    if (!token) {
      return finish();
    }
    endSession(token, (err, _data) => {
      if (err) {
        fail(res, 500, "couldn't end session", err);
        return;
      }
      finish();
    });
  }
  function hashStringToInt32(s) {
    let h = 1;
    if (typeof s !== 'string' || !s.length) {
      return 99;
    }
    for (let i = 0; i < s.length; i++) {
      h = h * s.charCodeAt(i) * 31;
    }
    if (h < 0) {
      h = -h;
    }
    while (h > 2147483648) {
      h = h / 2;
    }
    return h;
  }
  function handle_POST_metrics(req, res) {
    const enabled = false;
    if (!enabled) {
      return res.status(200).json({});
    }
    const pc = req.cookies[COOKIES.PERMANENT_COOKIE];
    const hashedPc = hashStringToInt32(pc);
    const uid = req.p.uid || null;
    const durs = req.p.durs.map((dur) => {
      if (dur === -1) {
        dur = null;
      }
      return dur;
    });
    const clientTimestamp = req.p.clientTimestamp;
    const ages = req.p.times.map((t) => clientTimestamp - t);
    const now = Date.now();
    const timesInTermsOfServerTime = ages.map((a) => now - a);
    const len = timesInTermsOfServerTime.length;
    const entries = [];
    for (let i = 0; i < len; i++) {
      entries.push(`(${[uid || 'null', req.p.types[i], durs[i], hashedPc, timesInTermsOfServerTime[i]].join(',')})`);
    }
    pgQueryP(`insert into metrics (uid, type, dur, hashedPc, created) values ${entries.join(',')};`, [])
      .then((_result) => {
        res.json({});
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_metrics_post', err);
      });
  }
  function handle_GET_zinvites(req, res) {
    pgQuery_readOnly(
      'SELECT * FROM conversations WHERE zid = ($1) AND owner = ($2);',
      [req.p.zid, req.p.uid],
      (err, results) => {
        if (err) {
          fail(res, 500, 'polis_err_fetching_zinvite_invalid_conversation_or_owner', err);
          return;
        }
        if (!results || !results.rows) {
          res.writeHead(404);
          res.json({
            status: 404
          });
          return;
        }
        pgQuery_readOnly('SELECT * FROM zinvites WHERE zid = ($1);', [req.p.zid], (err, results) => {
          if (err) {
            fail(res, 500, 'polis_err_fetching_zinvite_invalid_conversation_or_owner_or_something', err);
            return;
          }
          if (!results || !results.rows) {
            res.writeHead(404);
            res.json({
              status: 404
            });
            return;
          }
          res.status(200).json({
            codes: results.rows
          });
        });
      }
    );
  }
  function generateConversationURLPrefix() {
    return `${_.random(2, 9)}`;
  }
  function generateSUZinvites(numTokens) {
    return new Promise((resolve, reject) => {
      generateToken(31 * numTokens, true, (err, longStringOfTokens) => {
        if (err) {
          reject(new Error('polis_err_creating_otzinvite'));
          return;
        }
        const otzinviteArrayRegexMatch = longStringOfTokens?.match(/.{1,31}/g);
        let otzinviteArray = otzinviteArrayRegexMatch?.slice(0, numTokens);
        otzinviteArray = otzinviteArray?.map((suzinvite) => generateConversationURLPrefix() + suzinvite);
        resolve(otzinviteArray);
      });
    });
  }
  function handle_POST_zinvites(req, res) {
    const generateShortUrl = req.p.short_url;
    pgQuery(
      'SELECT * FROM conversations WHERE zid = ($1) AND owner = ($2);',
      [req.p.zid, req.p.uid],
      (err, _results) => {
        if (err) {
          fail(res, 500, 'polis_err_creating_zinvite_invalid_conversation_or_owner', err);
          return;
        }
        generateAndRegisterZinvite(req.p.zid, generateShortUrl)
          .then((zinvite) => {
            res.status(200).json({
              zinvite: zinvite
            });
          })
          .catch((err) => {
            fail(res, 500, 'polis_err_creating_zinvite', err);
          });
      }
    );
  }
  function checkZinviteCodeValidity(zid, zinvite, callback) {
    pgQuery_readOnly('SELECT * FROM zinvites WHERE zid = ($1) AND zinvite = ($2);', [zid, zinvite], (err, results) => {
      if (err || !results || !results.rows || !results.rows.length) {
        callback(1);
      } else {
        callback(null);
      }
    });
  }
  function addConversationId(o, dontUseCache) {
    if (!o.zid) {
      return Promise.resolve(o);
    }
    return getZinvite(o.zid, dontUseCache).then((conversation_id) => {
      o.conversation_id = conversation_id;
      return o;
    });
  }
  function addConversationIds(a) {
    const zids = [];
    for (let i = 0; i < a.length; i++) {
      if (a[i].zid) {
        zids.push(a[i].zid);
      }
    }
    if (!zids.length) {
      return Promise.resolve(a);
    }
    return getZinvites(zids).then((zid2conversation_id) =>
      a.map((o) => {
        o.conversation_id = zid2conversation_id[o.zid];
        return o;
      })
    );
  }
  function finishOne(res, o, dontUseCache, altStatusCode) {
    addConversationId(o, dontUseCache)
      .then(
        (item) => {
          if (item.zid) {
            item.zid = undefined;
          }
          const statusCode = altStatusCode || 200;
          res.status(statusCode).json(item);
        },
        (err) => {
          fail(res, 500, 'polis_err_finishing_responseA', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_finishing_response', err);
      });
  }
  function finishArray(res, a) {
    addConversationIds(a)
      .then(
        (items) => {
          if (items) {
            for (let i = 0; i < items.length; i++) {
              if (items[i].zid) {
                items[i].zid = undefined;
              }
            }
          }
          res.status(200).json(items);
        },
        (err) => {
          fail(res, 500, 'polis_err_finishing_response2A', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_finishing_response2', err);
      });
  }
  function checkSuzinviteCodeValidity(zid, suzinvite, callback) {
    pgQuery('SELECT * FROM suzinvites WHERE zid = ($1) AND suzinvite = ($2);', [zid, suzinvite], (err, results) => {
      if (err || !results || !results.rows || !results.rows.length) {
        callback(1);
      } else {
        callback(null);
      }
    });
  }
  function getSUZinviteInfo(suzinvite) {
    return new Promise((resolve, reject) => {
      pgQuery('SELECT * FROM suzinvites WHERE suzinvite = ($1);', [suzinvite], (err, results) => {
        if (err) {
          return reject(err);
        }
        if (!results || !results.rows || !results.rows.length) {
          return reject(new Error('polis_err_no_matching_suzinvite'));
        }
        resolve(results.rows[0]);
      });
    });
  }
  const deleteSuzinvite = async (suzinvite) => {
    try {
      await pgQuery('DELETE FROM suzinvites WHERE suzinvite = ($1);', [suzinvite]);
    } catch (err) {
      logger.error('polis_err_removing_suzinvite', err);
    }
  };
  function xidExists(xid, owner, uid) {
    return pgQueryP('select * from xids where xid = ($1) and owner = ($2) and uid = ($3);', [xid, owner, uid]).then(
      (rows) => rows?.length
    );
  }
  const createXidEntry = async (xid, owner, uid) => {
    try {
      await pgQueryP('INSERT INTO xids (uid, owner, xid) VALUES ($1, $2, $3);', [uid, owner, xid]);
    } catch (err) {
      logger.error('polis_err_adding_xid_entry', err);
      throw new Error('polis_err_adding_xid_entry');
    }
  };
  function saveParticipantMetadataChoicesP(zid, pid, answers) {
    return new Promise((resolve, reject) => {
      saveParticipantMetadataChoices(zid, pid, answers, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve(0);
        }
      });
    });
  }
  function saveParticipantMetadataChoices(zid, pid, answers, callback) {
    if (!answers || !answers.length) {
      return callback(0);
    }
    const q = `select * from participant_metadata_answers where zid = ($1) and pmaid in (${answers.join(',')});`;
    pgQuery(q, [zid], (err, qa_results) => {
      if (err) {
        logger.error('polis_err_getting_participant_metadata_answers', err);
        return callback(err);
      }
      qa_results = qa_results.rows;
      qa_results = _.indexBy(qa_results, 'pmaid');
      answers = answers.map((pmaid) => {
        const pmqid = qa_results[pmaid].pmqid;
        return [zid, pid, pmaid, pmqid];
      });
      async.map(
        answers,
        (x, cb) => {
          pgQuery(
            'INSERT INTO participant_metadata_choices (zid, pid, pmaid, pmqid) VALUES ($1,$2,$3,$4);',
            x,
            (err, _results) => {
              if (err) {
                logger.error('polis_err_saving_participant_metadata_choices', err);
                return cb(err);
              }
              cb(0);
            }
          );
        },
        (err) => {
          if (err) {
            logger.error('polis_err_saving_participant_metadata_choices', err);
            return callback(err);
          }
          callback(0);
        }
      );
    });
  }
  function createParticpantLocationRecord(zid, uid, pid, lat, lng, source) {
    return pgQueryP('insert into participant_locations (zid, uid, pid, lat, lng, source) values ($1,$2,$3,$4,$5,$6);', [
      zid,
      uid,
      pid,
      lat,
      lng,
      source
    ]);
  }
  const LOCATION_SOURCES = {
    Twitter: 400,
    Facebook: 300,
    HTML5: 200,
    IP: 100,
    manual_entry: 1
  };
  function getUsersLocationName(uid) {
    return Promise.all([
      pgQueryP_readOnly('select * from facebook_users where uid = ($1);', [uid]),
      pgQueryP_readOnly('select * from twitter_users where uid = ($1);', [uid])
    ]).then((o) => {
      const fb = o[0]?.[0];
      const tw = o[1]?.[0];
      if (fb && _.isString(fb.location)) {
        return {
          location: fb.location,
          source: LOCATION_SOURCES.Facebook
        };
      }
      if (tw && _.isString(tw.location)) {
        return {
          location: tw.location,
          source: LOCATION_SOURCES.Twitter
        };
      }
      return null;
    });
  }
  function populateParticipantLocationRecordIfPossible(zid, uid, pid) {
    getUsersLocationName(uid)
      .then((locationData) => {
        if (!locationData || !process.env.GOOGLE_API_KEY) {
          return;
        }
        geoCode(locationData.location)
          .then((o) => {
            createParticpantLocationRecord(zid, uid, pid, o.lat, o.lng, locationData.source).catch((err) => {
              if (!isDuplicateKey(err)) {
                logger.error('polis_err_creating_particpant_location_record', err);
              }
            });
          })
          .catch((err) => {
            logger.error('polis_err_geocoding', err);
          });
      })
      .catch((err) => {
        logger.error('polis_err_fetching_user_location_name', err);
      });
  }
  function updateLastInteractionTimeForConversation(zid, uid) {
    return pgQueryP(
      'update participants set last_interaction = now_as_millis(), nsli = 0 where zid = ($1) and uid = ($2);',
      [zid, uid]
    );
  }
  function addExtendedParticipantInfo(zid, uid, data) {
    if (!data || !_.keys(data).length) {
      return Promise.resolve();
    }
    const params = Object.assign({}, data, {
      zid: zid,
      uid: uid,
      modified: 9876543212345
    });
    const qUpdate = sql_participants_extended
      .update(params)
      .where(sql_participants_extended.zid.equals(zid))
      .and(sql_participants_extended.uid.equals(uid));
    let qString = qUpdate.toString();
    qString = qString.replace('9876543212345', 'now_as_millis()');
    return pgQueryP(qString, []);
  }
  function tryToJoinConversation(zid, uid, info, pmaid_answers) {
    function doAddExtendedParticipantInfo() {
      if (info && _.keys(info).length > 0) {
        addExtendedParticipantInfo(zid, uid, info);
      }
    }
    function saveMetadataChoices(pid) {
      if (pmaid_answers?.length) {
        saveParticipantMetadataChoicesP(zid, pid, pmaid_answers);
      }
    }
    return addParticipant(zid, uid).then((rows) => {
      const pid = rows?.[0]?.pid;
      const ptpt = rows[0];
      doAddExtendedParticipantInfo();
      if (pmaid_answers?.length) {
        saveMetadataChoices();
      }
      populateParticipantLocationRecordIfPossible(zid, uid, pid);
      return ptpt;
    });
  }
  function addParticipantAndMetadata(zid, uid, req, permanent_cookie) {
    const info = {};
    const parent_url = req?.cookies?.[COOKIES.PARENT_URL] || req?.p?.parent_url;
    const referer = req?.cookies[COOKIES.PARENT_REFERRER] || req?.headers?.referer || req?.headers?.referrer;
    if (parent_url) {
      info.parent_url = parent_url;
    }
    if (referer) {
      info.referrer = referer;
    }
    if (Config.applicationName === 'PolisWebServer') {
      const x_forwarded_for = req?.headers?.['x-forwarded-for'];
      let ip = null;
      if (x_forwarded_for) {
        let ips = x_forwarded_for;
        ips = ips?.split(', ');
        ip = ips.length && ips[0];
        info.encrypted_ip_address = encrypt(ip);
        info.encrypted_x_forwarded_for = encrypt(x_forwarded_for);
      }
    }
    if (permanent_cookie) {
      info.permanent_cookie = permanent_cookie;
    }
    if (req?.headers?.origin) {
      info.origin = req?.headers?.origin;
    }
    return addParticipant(zid, uid).then((rows) => {
      const ptpt = rows[0];
      const pid = ptpt.pid;
      populateParticipantLocationRecordIfPossible(zid, uid, pid);
      addExtendedParticipantInfo(zid, uid, info);
      return rows;
    });
  }
  function joinConversation(zid, uid, info, pmaid_answers) {
    function tryJoin() {
      return tryToJoinConversation(zid, uid, info, pmaid_answers);
    }
    function doJoin() {
      const promise = tryJoin()
        .catch(tryJoin)
        .catch(tryJoin)
        .catch(tryJoin)
        .catch(tryJoin)
        .catch(tryJoin)
        .catch(tryJoin)
        .catch(tryJoin)
        .catch(tryJoin)
        .catch(tryJoin);
      return promise;
    }
    return getPidPromise(zid, uid).then((pid) => {
      if (pid >= 0) {
        return;
      }
      return doJoin();
    }, doJoin);
  }
  function isOwnerOrParticipant(zid, uid, callback) {
    getPid(zid, uid, (err, pid) => {
      if (err || pid < 0) {
        isConversationOwner(zid, uid, (err) => {
          callback?.(err);
        });
      } else {
        callback?.(null);
      }
    });
  }
  function isConversationOwner(zid, uid, callback) {
    pgQuery_readOnly('SELECT * FROM conversations WHERE zid = ($1) AND owner = ($2);', [zid, uid], (err, docs) => {
      if (!docs || !docs.rows || docs.rows.length === 0) {
        err = err || 1;
      }
      callback?.(err);
    });
  }
  function isOwner(zid, uid) {
    return getConversationInfo(zid).then((info) => info.owner === uid);
  }
  function isModerator(zid, uid) {
    if (isPolisDev(uid)) {
      return Promise.resolve(true);
    }
    return pgQueryP_readOnly(
      'select count(*) from conversations where owner in (select uid from users where site_id = (select site_id from users where uid = ($2))) and zid = ($1);',
      [zid, uid]
    ).then((rows) => rows[0].count >= 1);
  }
  function getParticipant(zid, uid) {
    return new MPromise('getParticipant', (resolve, reject) => {
      pgQuery_readOnly('SELECT * FROM participants WHERE zid = ($1) AND uid = ($2);', [zid, uid], (err, results) => {
        if (err) {
          return reject(err);
        }
        if (!results || !results.rows) {
          return reject(new Error('polis_err_getParticipant_failed'));
        }
        resolve(results.rows[0]);
      });
    });
  }
  function getAnswersForConversation(zid, callback) {
    pgQuery_readOnly('SELECT * from participant_metadata_answers WHERE zid = ($1) AND alive=TRUE;', [zid], (err, x) => {
      if (err) {
        callback(err);
        return;
      }
      callback(0, x.rows);
    });
  }
  function getChoicesForConversation(zid) {
    return new Promise((resolve, reject) => {
      pgQuery_readOnly(
        'select * from participant_metadata_choices where zid = ($1) and alive = TRUE;',
        [zid],
        (err, x) => {
          if (err) {
            reject(err);
            return;
          }
          if (!x || !x.rows) {
            resolve([]);
            return;
          }
          resolve(x.rows);
        }
      );
    });
  }
  const getUserInfoForUid = User.getUserInfoForUid;
  const getUserInfoForUid2 = User.getUserInfoForUid2;
  function emailFeatureRequest(message) {
    const body = `Somebody clicked a dummy button!

${message}`;
    return sendMultipleTextEmails(polisFromAddress, adminEmails, 'Dummy button clicked!!!', body).catch((err) => {
      logger.error('polis_err_failed_to_email_for_dummy_button', {
        message,
        err
      });
    });
  }
  function emailTeam(subject, body) {
    return sendMultipleTextEmails(polisFromAddress, adminEmails, subject, body).catch((err) => {
      logger.error('polis_err_failed_to_email_team', err);
    });
  }
  function emailBadProblemTime(message) {
    const body = `Yo, there was a serious problem. Here's the message:

${message}`;
    return emailTeam('Polis Bad Problems!!!', body);
  }
  function sendPasswordResetEmail(uid, pwresettoken, serverName, callback) {
    getUserInfoForUid(uid, (err, userInfo) => {
      if (err) {
        return callback?.(err);
      }
      if (!userInfo) {
        return callback?.('missing user info');
      }
      const body = `Hi ${userInfo.hname},

We have just received a password reset request for ${userInfo.email}

To reset your password, visit this page:
${serverName}/pwreset/${pwresettoken}

"Thank you for using Polis`;
      sendTextEmail(polisFromAddress, userInfo.email, 'Polis Password Reset', body)
        .then(() => {
          callback?.();
        })
        .catch((err) => {
          logger.error('polis_err_failed_to_email_password_reset_code', err);
          callback?.(err);
        });
    });
  }
  function sendMultipleTextEmails(sender, recipientArray, subject, text) {
    recipientArray = recipientArray || [];
    return Promise.all(
      recipientArray.map((email) => {
        const promise = sendTextEmail(sender, email, subject, text);
        promise.catch((err) => {
          logger.error('polis_err_failed_to_email_for_user', { email, err });
        });
        return promise;
      })
    );
  }
  function trySendingBackupEmailTest() {
    if (devMode) {
      return;
    }
    const d = new Date();
    if (d.getDay() === 1) {
      sendTextEmailWithBackupOnly(
        polisFromAddress,
        Config.adminEmailEmailTest,
        'monday backup email system test',
        'seems to be working'
      );
    }
  }
  setInterval(trySendingBackupEmailTest, 1000 * 60 * 60 * 23);
  trySendingBackupEmailTest();
  function sendEinviteEmail(req, email, einvite) {
    const serverName = getServerNameWithProtocol(req);
    const body = `Welcome to pol.is!

Click this link to open your account:

${serverName}/welcome/${einvite}

Thank you for using Polis`;
    return sendTextEmail(polisFromAddress, email, 'Get Started with Polis', body);
  }
  function isEmailVerified(email) {
    return dbPgQuery
      .queryP('select * from email_validations where email = ($1);', [email])
      .then((rows) => rows.length > 0);
  }
  function handle_GET_verification(req, res) {
    const einvite = req.p.e;
    pgQueryP('select * from einvites where einvite = ($1);', [einvite])
      .then((rows) => {
        if (!rows.length) {
          fail(res, 500, 'polis_err_verification_missing');
        }
        const email = rows[0].email;
        return pgQueryP('select email from email_validations where email = ($1);', [email]).then((rows) => {
          if (rows && rows.length > 0) {
            return true;
          }
          return pgQueryP('insert into email_validations (email) values ($1);', [email]);
        });
      })
      .then(() => {
        res.set('Content-Type', 'text/html');
        res.send(`<html><body>
<div style='font-family: Futura, Helvetica, sans-serif;'>
Email verified! You can close this tab or hit the back button.
</div>
</body></html>`);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_verification', err);
      });
  }
  function paramsToStringSortedByName(params) {
    const pairs = _.pairs(params).sort((a, b) => a[0] > b[0]);
    const pairsList = pairs.map((pair) => pair.join('='));
    return pairsList.join('&');
  }
  const HMAC_SIGNATURE_PARAM_NAME = 'signature';
  function createHmacForQueryParams(path, params) {
    path = path.replace(/\/$/, '');
    const s = `${path}?${paramsToStringSortedByName(params)}`;
    const hmac = crypto.createHmac('sha1', 'G7f387ylIll8yuskuf2373rNBmcxqWYFfHhdsd78f3uekfs77EOLR8wofw');
    hmac.setEncoding('hex');
    hmac.write(s);
    hmac.end();
    const hash = hmac.read();
    return hash;
  }
  const verifyHmacForQueryParams = (path, params) => {
    return new Promise((resolve, reject) => {
      const clonedParams = { ...params };
      const hash = clonedParams[HMAC_SIGNATURE_PARAM_NAME];
      delete clonedParams[HMAC_SIGNATURE_PARAM_NAME];
      const correctHash = createHmacForQueryParams(path, clonedParams);
      setTimeout(() => {
        logger.debug('comparing', { correctHash, hash });
        if (correctHash === hash) {
          resolve();
        } else {
          reject();
        }
      });
    });
  };
  function sendEmailByUid(uid, subject, body) {
    return getUserInfoForUid2(uid).then((userInfo) =>
      sendTextEmail(
        polisFromAddress,
        userInfo.hname ? `${userInfo.hname} <${userInfo.email}>` : userInfo.email,
        subject,
        body
      )
    );
  }
  function handle_GET_participants(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    pgQueryP_readOnly('select * from participants where uid = ($1) and zid = ($2)', [uid, zid])
      .then((rows) => {
        const ptpt = (rows?.length && rows[0]) || null;
        res.status(200).json(ptpt);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_get_participant', err);
      });
  }
  function handle_GET_dummyButton(req, res) {
    const message = `${req.p.button} ${req.p.uid}`;
    emailFeatureRequest(message);
    res.status(200).end();
  }
  function doGetConversationsRecent(req, res, field) {
    if (!isPolisDev(req.p.uid)) {
      fail(res, 403, 'polis_err_no_access_for_this_user');
      return;
    }
    let time = req.p.sinceUnixTimestamp;
    if (_.isUndefined(time)) {
      time = Date.now() - 1000 * 60 * 60 * 24 * 7;
    } else {
      time *= 1000;
    }
    time = Number.parseInt(time);
    pgQueryP_readOnly(`select * from conversations where ${field} >= ($1);`, [time])
      .then((rows) => {
        res.json(rows);
      })
      .catch((err) => {
        fail(res, 403, 'polis_err_conversationsRecent', err);
      });
  }
  function handle_GET_conversationsRecentlyStarted(req, res) {
    doGetConversationsRecent(req, res, 'created');
  }
  function handle_GET_conversationsRecentActivity(req, res) {
    doGetConversationsRecent(req, res, 'modified');
  }
  function userHasAnsweredZeQuestions(zid, answers) {
    return new MPromise('userHasAnsweredZeQuestions', (resolve, reject) => {
      getAnswersForConversation(zid, (err, available_answers) => {
        if (err) {
          reject(err);
          return;
        }
        const q2a = _.indexBy(available_answers, 'pmqid');
        const a2q = _.indexBy(available_answers, 'pmaid');
        for (let i = 0; i < answers.length; i++) {
          const pmqid = a2q[answers[i]].pmqid;
          delete q2a[pmqid];
        }
        const remainingKeys = _.keys(q2a);
        const missing = remainingKeys && remainingKeys.length > 0;
        if (missing) {
          return reject(new Error(`polis_err_metadata_not_chosen_pmqid_${remainingKeys[0]}`));
        }
        return resolve();
      });
    });
  }
  function handle_POST_participants(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const answers = req.p.answers;
    const info = {};
    const parent_url = req.cookies[COOKIES.PARENT_URL] || req.p.parent_url;
    const referrer = req.cookies[COOKIES.PARENT_REFERRER] || req.p.referrer;
    if (parent_url) {
      info.parent_url = parent_url;
    }
    if (referrer) {
      info.referrer = referrer;
    }
    function finish(ptpt) {
      clearCookie(req, res, COOKIES.PARENT_URL);
      clearCookie(req, res, COOKIES.PARENT_REFERRER);
      setTimeout(() => {
        updateLastInteractionTimeForConversation(zid, uid);
      }, 0);
      res.status(200).json(ptpt);
    }
    function doJoin() {
      userHasAnsweredZeQuestions(zid, answers).then(
        () => {
          joinConversation(zid, uid, info, answers).then(
            (ptpt) => {
              finish(ptpt);
            },
            (err) => {
              fail(res, 500, 'polis_err_add_participant', err);
            }
          );
        },
        (err) => {
          fail(res, 400, err.message, err);
        }
      );
    }
    getParticipant(zid, req.p.uid)
      .then(
        (ptpt) => {
          if (ptpt) {
            finish(ptpt);
            populateParticipantLocationRecordIfPossible(zid, req.p.uid, ptpt.pid);
            addExtendedParticipantInfo(zid, req.p.uid, info);
            return;
          }
          getConversationInfo(zid)
            .then(() => {
              doJoin();
            })
            .catch((err) => {
              fail(res, 500, 'polis_err_post_participants_need_uid_to_check_lti_users_4', err);
            });
        },
        (err) => {
          fail(res, 500, 'polis_err_post_participants_db_err', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_post_participants_misc', err);
      });
  }
  function subscribeToNotifications(zid, uid, email) {
    const type = 1;
    logger.info('subscribeToNotifications', { zid, uid });
    return pgQueryP('update participants_extended set subscribe_email = ($3) where zid = ($1) and uid = ($2);', [
      zid,
      uid,
      email
    ]).then(() =>
      pgQueryP('update participants set subscribed = ($3) where zid = ($1) and uid = ($2);', [zid, uid, type]).then(
        (_rows) => type
      )
    );
  }
  function unsubscribeFromNotifications(zid, uid) {
    const type = 0;
    return pgQueryP('update participants set subscribed = ($3) where zid = ($1) and uid = ($2);', [
      zid,
      uid,
      type
    ]).then((_rows) => type);
  }
  function addNotificationTask(zid) {
    return pgQueryP(
      'insert into notification_tasks (zid) values ($1) on conflict (zid) do update set modified = now_as_millis();',
      [zid]
    );
  }
  function maybeAddNotificationTask(zid, timeInMillis) {
    return pgQueryP('insert into notification_tasks (zid, modified) values ($1, $2) on conflict (zid) do nothing;', [
      zid,
      timeInMillis
    ]);
  }
  function claimNextNotificationTask() {
    return pgQueryP(
      'delete from notification_tasks where zid = (select zid from notification_tasks order by random() for update skip locked limit 1) returning *;'
    ).then((rows) => {
      if (!rows || !rows.length) {
        return null;
      }
      return rows[0];
    });
  }
  function getDbTime() {
    return pgQueryP('select now_as_millis();', []).then((rows) => {
      return rows[0].now_as_millis;
    });
  }
  function doNotificationsForZid(zid, timeOfLastEvent) {
    let shouldTryAgain = false;
    return pgQueryP('select * from participants where zid = ($1) and last_notified < ($2) and subscribed > 0;', [
      zid,
      timeOfLastEvent
    ])
      .then((candidates) => {
        if (!candidates || !candidates.length) {
          return null;
        }
        candidates = candidates.map((ptpt) => {
          ptpt.last_notified = Number(ptpt.last_notified);
          ptpt.last_interaction = Number(ptpt.last_interaction);
          return ptpt;
        });
        return Promise.all([getDbTime(), getConversationInfo(zid), getZinvite(zid)]).then((a) => {
          const dbTimeMillis = a[0];
          const conv = a[1];
          const conversation_id = a[2];
          const url = conv.parent_url || `https://pol.is/${conversation_id}`;
          const pid_to_ptpt = {};
          candidates.forEach((c) => {
            pid_to_ptpt[c.pid] = c;
          });
          return BluebirdPromise.mapSeries(candidates, (item, _index, _length) => {
            return getNumberOfCommentsRemaining(item.zid, item.pid).then((rows) => {
              return rows[0];
            });
          }).then((results) => {
            const needNotification = results.filter((result) => {
              const ptpt = pid_to_ptpt[result.pid];
              let needs = true;
              needs = needs && result.remaining > 0;
              let waitTime = 60 * 60 * 1000;
              if (ptpt.nsli === 0) {
                waitTime = 60 * 60 * 1000;
              } else if (ptpt.nsli === 1) {
                waitTime = 2 * 60 * 60 * 1000;
              } else if (ptpt.nsli === 2) {
                waitTime = 24 * 60 * 60 * 1000;
              } else if (ptpt.nsli === 3) {
                waitTime = 48 * 60 * 60 * 1000;
              } else {
                needs = false;
              }
              if (needs && dbTimeMillis < ptpt.last_notified + waitTime) {
                shouldTryAgain = true;
                needs = false;
              }
              if (needs && dbTimeMillis < ptpt.last_interaction + 5 * 60 * 1000) {
                shouldTryAgain = true;
                needs = false;
              }
              if (devMode) {
                needs = needs && isPolisDev(ptpt.uid);
              }
              return needs;
            });
            if (needNotification.length === 0) {
              return null;
            }
            const pids = _.pluck(needNotification, 'pid');
            return pgQueryP(
              `select uid, subscribe_email from participants_extended where uid in (select uid from participants where pid in (${pids.join(',')}));`,
              []
            ).then((rows) => {
              const uidToEmail = {};
              rows.forEach((row) => {
                uidToEmail[row.uid] = row.subscribe_email;
              });
              return BluebirdPromise.each(needNotification, (item, _index, _length) => {
                const uid = pid_to_ptpt[item.pid].uid;
                return sendNotificationEmail(uid, url, conversation_id, uidToEmail[uid], item.remaining).then(() => {
                  return pgQueryP(
                    'update participants set last_notified = now_as_millis(), nsli = nsli + 1 where uid = ($1) and zid = ($2);',
                    [uid, zid]
                  );
                });
              });
            });
          });
        });
      })
      .then(() => {
        return shouldTryAgain;
      });
  }
  function doNotificationBatch() {
    return claimNextNotificationTask().then((task) => {
      if (!task) {
        return Promise.resolve();
      }
      return doNotificationsForZid(task.zid, task.modified).then((shouldTryAgain) => {
        if (shouldTryAgain) {
          maybeAddNotificationTask(task.zid, task.modified);
        }
      });
    });
  }
  function doNotificationLoop() {
    logger.debug('doNotificationLoop');
    doNotificationBatch().then(() => {
      setTimeout(doNotificationLoop, 10000);
    });
  }
  function sendNotificationEmail(uid, url, conversation_id, email, _remaining) {
    const subject = `New statements to vote on (conversation ${conversation_id})`;
    let body = 'There are new statements available for you to vote on here:\n';
    body += '\n';
    body += `${url}\n`;
    body += '\n';
    body +=
      "You're receiving this message because you're signed up to receive Polis notifications for this conversation. You can unsubscribe from these emails by clicking this link:\n";
    body += `${createNotificationsUnsubscribeUrl(conversation_id, email)}\n`;
    body += '\n';
    body +=
      "If for some reason the above link does not work, please reply directly to this email with the message 'Unsubscribe' and we will remove you within 24 hours.";
    body += '\n';
    body += 'Thanks for your participation';
    return sendEmailByUid(uid, subject, body);
  }
  const shouldSendNotifications = !devMode;
  if (shouldSendNotifications) {
    doNotificationLoop();
  }
  function createNotificationsUnsubscribeUrl(conversation_id, email) {
    const params = {
      conversation_id: conversation_id,
      email: encode(email)
    };
    const path = 'api/v3/notifications/unsubscribe';
    params[HMAC_SIGNATURE_PARAM_NAME] = createHmacForQueryParams(path, params);
    const server = Config.getServerUrl();
    return `${server}/${path}?${paramsToStringSortedByName(params)}`;
  }
  function createNotificationsSubscribeUrl(conversation_id, email) {
    const params = {
      conversation_id: conversation_id,
      email: encode(email)
    };
    const path = 'api/v3/notifications/subscribe';
    params[HMAC_SIGNATURE_PARAM_NAME] = createHmacForQueryParams(path, params);
    const server = Config.getServerUrl();
    return `${server}/${path}?${paramsToStringSortedByName(params)}`;
  }
  function handle_GET_notifications_subscribe(req, res) {
    const zid = req.p.zid;
    const email = req.p.email;
    const params = {
      conversation_id: req.p.conversation_id,
      email: req.p.email
    };
    params[HMAC_SIGNATURE_PARAM_NAME] = req.p[HMAC_SIGNATURE_PARAM_NAME];
    verifyHmacForQueryParams('api/v3/notifications/subscribe', params)
      .then(
        () =>
          pgQueryP(
            'update participants set subscribed = 1 where uid = (select uid from users where email = ($2)) and zid = ($1);',
            [zid, email]
          ).then(() => {
            res.set('Content-Type', 'text/html');
            res.send(`<h1>Subscribed!</h1>
<p>
<a href="${createNotificationsUnsubscribeUrl(req.p.conversation_id, req.p.email)}">oops, unsubscribe me.</a>
</p>`);
          }),
        () => {
          fail(res, 403, 'polis_err_subscribe_signature_mismatch');
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_subscribe_misc', err);
      });
  }
  function handle_GET_notifications_unsubscribe(req, res) {
    const zid = req.p.zid;
    const email = req.p.email;
    const params = {
      conversation_id: req.p.conversation_id,
      email: email
    };
    params[HMAC_SIGNATURE_PARAM_NAME] = req.p[HMAC_SIGNATURE_PARAM_NAME];
    verifyHmacForQueryParams('api/v3/notifications/unsubscribe', params)
      .then(
        () =>
          pgQueryP(
            'update participants set subscribed = 0 where uid = (select uid from users where email = ($2)) and zid = ($1);',
            [zid, email]
          ).then(() => {
            res.set('Content-Type', 'text/html');
            res.send(`<h1>Unsubscribed.</h1>
<p>
<a href="${createNotificationsSubscribeUrl(req.p.conversation_id, req.p.email)}">oops, subscribe me again.</a>
</p>`);
          }),
        () => {
          fail(res, 403, 'polis_err_unsubscribe_signature_mismatch');
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_unsubscribe_misc', err);
      });
  }
  function handle_POST_convSubscriptions(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const type = req.p.type;
    const email = req.p.email;
    function finish(type) {
      res.status(200).json({
        subscribed: type
      });
    }
    if (type === 1) {
      subscribeToNotifications(zid, uid, email)
        .then(finish)
        .catch((err) => {
          fail(res, 500, `polis_err_sub_conv ${zid} ${uid}`, err);
        });
    } else if (type === 0) {
      unsubscribeFromNotifications(zid, uid)
        .then(finish)
        .catch((err) => {
          fail(res, 500, `polis_err_unsub_conv ${zid} ${uid}`, err);
        });
    } else {
      fail(res, 400, 'polis_err_bad_subscription_type', new Error('polis_err_bad_subscription_type'));
    }
  }
  function handle_POST_auth_login(req, res) {
    const password = req.p.password;
    let email = req.p.email || '';
    email = email.toLowerCase();
    if (!_.isString(password) || !password.length) {
      fail(res, 403, 'polis_err_login_need_password');
      return;
    }
    pgQuery('SELECT * FROM users WHERE LOWER(email) = ($1);', [email], (err, docs) => {
      const { rows } = docs;
      if (err) {
        fail(res, 403, 'polis_err_login_unknown_user_or_password', err);
        return;
      }
      if (!rows || rows.length === 0) {
        fail(res, 403, 'polis_err_login_unknown_user_or_password_noresults');
        return;
      }
      const uid = rows[0].uid;
      pgQuery('select pwhash from jianiuevyew where uid = ($1);', [uid], (err, results) => {
        const { rows } = results;
        if (err) {
          fail(res, 403, 'polis_err_login_unknown_user_or_password', err);
          return;
        }
        if (!results || rows.length === 0) {
          fail(res, 403, 'polis_err_login_unknown_user_or_password');
          return;
        }
        const hashedPassword = rows[0].pwhash;
        bcrypt.compare(password, hashedPassword, (errCompare, result) => {
          logger.debug('errCompare, result', { errCompare, result });
          if (errCompare || !result) {
            fail(res, 403, 'polis_err_login_unknown_user_or_password');
            return;
          }
          startSession(uid, (_errSess, token) => {
            const response_data = {
              uid: uid,
              email: email,
              token: token
            };
            addCookies(req, res, token, uid)
              .then(() => {
                res.json(response_data);
              })
              .catch((err) => {
                fail(res, 500, 'polis_err_adding_cookies', err);
              });
          });
        });
      });
    });
  }
  function handle_POST_joinWithInvite(req, res) {
    return joinWithZidOrSuzinvite({
      answers: req.p.answers,
      existingAuth: !!req.p.uid,
      suzinvite: req.p.suzinvite,
      permanentCookieToken: req.p.permanentCookieToken,
      uid: req.p.uid,
      zid: req.p.zid,
      referrer: req.p.referrer,
      parent_url: req.p.parent_url
    })
      .then((o) => {
        const uid = o.uid;
        logger.info(`startSessionAndAddCookies ${uid} existing ${o.existingAuth}`);
        if (!o.existingAuth) {
          return startSessionAndAddCookies(req, res, uid).then(() => o);
        }
        return Promise.resolve(o);
      })
      .then((o) => {
        logger.info('permanentCookieToken', o.permanentCookieToken);
        if (o.permanentCookieToken) {
          return recordPermanentCookieZidJoin(o.permanentCookieToken, o.zid).then(
            () => o,
            () => o
          );
        }
        return o;
      })
      .then((o) => {
        const pid = o.pid;
        res.status(200).json({
          pid: pid,
          uid: req.p.uid
        });
      })
      .catch((err) => {
        if (err?.message?.match(/polis_err_need_full_user/)) {
          fail(res, 403, err.message, err);
        } else if (err?.message) {
          fail(res, 500, err.message, err);
        } else if (err) {
          fail(res, 500, 'polis_err_joinWithZidOrSuzinvite', err);
        } else {
          fail(res, 500, 'polis_err_joinWithZidOrSuzinvite');
        }
      });
  }
  function joinWithZidOrSuzinvite(o) {
    return Promise.resolve(o)
      .then((o) => {
        if (o.suzinvite) {
          return getSUZinviteInfo(o.suzinvite).then((suzinviteInfo) => Object.assign(o, suzinviteInfo));
        }
        if (o.zid) {
          return o;
        }
        throw new Error('polis_err_missing_invite');
      })
      .then((o) => {
        logger.info('joinWithZidOrSuzinvite convinfo begin');
        return getConversationInfo(o.zid).then((conv) => {
          logger.info('joinWithZidOrSuzinvite convinfo done');
          o.conv = conv;
          return o;
        });
      })
      .then((o) => o)
      .then((o) => {
        logger.info('joinWithZidOrSuzinvite userinfo begin');
        if (!o.uid) {
          logger.info('joinWithZidOrSuzinvite userinfo no uid');
          return o;
        }
        return getUserInfoForUid2(o.uid).then((user) => {
          logger.info('joinWithZidOrSuzinvite userinfo done');
          o.user = user;
          return o;
        });
      })
      .then((o) => {
        if (o.uid) {
          return o;
        }
        return createDummyUser().then((uid) =>
          Object.assign(o, {
            uid: uid
          })
        );
      })
      .then((o) => userHasAnsweredZeQuestions(o.zid, o.answers).then(() => o))
      .then((o) => {
        const info = {};
        if (o.referrer) {
          info.referrer = o.referrer;
        }
        if (o.parent_url) {
          info.parent_url = o.parent_url;
        }
        return joinConversation(o.zid, o.uid, info, o.answers).then((ptpt) => Object.assign(o, ptpt));
      })
      .then((o) => {
        if (o.xid) {
          return xidExists(o.xid, o.conv.org_id, o.uid).then((exists) => {
            if (exists) {
              return o;
            }
            const shouldCreateXidEntryPromise = o.conv.use_xid_whitelist
              ? isXidWhitelisted(o.conv.owner, o.xid)
              : Promise.resolve(true);
            shouldCreateXidEntryPromise.then((should) => {
              if (should) {
                return createXidEntry(o.xid, o.conv.org_id, o.uid).then(() => o);
              }
              throw new Error('polis_err_xid_not_whitelisted');
            });
          });
        }
        return o;
      })
      .then((o) => {
        if (o.suzinvite) {
          return deleteSuzinvite(o.suzinvite).then(() => o);
        }
        return o;
      });
  }
  function startSessionAndAddCookies(req, res, uid) {
    return new Promise((resolve, reject) => {
      startSession(uid, (err, token) => {
        if (err) {
          reject(new Error('polis_err_reg_failed_to_start_session'));
          return;
        }
        resolve(addCookies(req, res, token, uid));
      });
    });
  }
  function deleteFacebookUserRecord(o) {
    if (!isPolisDev(o.uid)) {
      return Promise.reject('polis_err_not_implemented');
    }
    return pgQueryP('delete from facebook_users where uid = ($1);', [o.uid]);
  }
  function createFacebookUserRecord(o) {
    const profileInfo = o.fb_public_profile;
    return pgQueryP(
      'insert into facebook_users (uid, fb_user_id, fb_name, fb_link, fb_public_profile, fb_login_status, fb_access_token, fb_granted_scopes, fb_location_id, location, fb_friends_response, response) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);',
      [
        o.uid,
        o.fb_user_id,
        profileInfo.name,
        profileInfo.link,
        JSON.stringify(o.fb_public_profile),
        o.fb_login_status,
        o.fb_access_token,
        o.fb_granted_scopes,
        profileInfo.locationInfo?.id,
        profileInfo.locationInfo?.name,
        o.fb_friends_response || '',
        o.response
      ]
    );
  }
  function updateFacebookUserRecord(o) {
    const profileInfo = o.fb_public_profile;
    const fb_public_profile_string = JSON.stringify(o.fb_public_profile);
    return pgQueryP(
      'update facebook_users set modified=now_as_millis(), fb_user_id=($2), fb_name=($3), fb_link=($4), fb_public_profile=($5), fb_login_status=($6), fb_access_token=($7), fb_granted_scopes=($8), fb_location_id=($9), location=($10), fb_friends_response=($11), response=($12) where uid = ($1);',
      [
        o.uid,
        o.fb_user_id,
        profileInfo.name,
        profileInfo.link,
        fb_public_profile_string,
        o.fb_login_status,
        o.fb_access_token,
        o.fb_granted_scopes,
        profileInfo.locationInfo?.id,
        profileInfo.locationInfo?.name,
        o.fb_friends_response || '',
        o.response
      ]
    );
  }
  function addFacebookFriends(uid, fb_friends_response) {
    const fbFriendIds = (fb_friends_response || [])
      .map((friend) => `${friend.id}`)
      .filter((id) => {
        const hasNonNumericalCharacters = /[^0-9]/.test(id);
        if (hasNonNumericalCharacters) {
          emailBadProblemTime(`found facebook ID with non-numerical characters ${id}`);
        }
        return !hasNonNumericalCharacters;
      })
      .map((id) => `'${id}'`);
    if (!fbFriendIds.length) {
      return Promise.resolve();
    }
    return pgQueryP(
      `insert into facebook_friends (uid, friend) select ($1), uid from facebook_users where fb_user_id in (${fbFriendIds.join(',')});`,
      [uid]
    );
  }
  function handle_GET_perfStats(_req, res) {
    res.json(METRICS_IN_RAM);
  }
  function getFirstForPid(votes) {
    const seen = {};
    const len = votes.length;
    const firstVotes = [];
    for (let i = 0; i < len; i++) {
      const vote = votes[i];
      if (!seen[vote.pid]) {
        firstVotes.push(vote);
        seen[vote.pid] = true;
      }
    }
    return firstVotes;
  }
  function isParentDomainWhitelisted(domain, zid, isWithinIframe, domain_whitelist_override_key) {
    return pgQueryP_readOnly(
      'select * from site_domain_whitelist where site_id = ' +
        '(select site_id from users where uid = ' +
        '(select owner from conversations where zid = ($1)));',
      [zid]
    ).then((rows) => {
      logger.debug('isParentDomainWhitelisted', {
        domain,
        zid,
        isWithinIframe
      });
      if (!rows || !rows.length || !rows[0].domain_whitelist.length) {
        logger.debug('isParentDomainWhitelisted : no whitelist');
        return true;
      }
      const whitelist = rows[0].domain_whitelist;
      const wdomains = whitelist.split(',');
      if (!isWithinIframe && wdomains.indexOf('*.pol.is') >= 0) {
        logger.debug('isParentDomainWhitelisted : *.pol.is');
        return true;
      }
      if (domain_whitelist_override_key && rows[0].domain_whitelist_override_key === domain_whitelist_override_key) {
        return true;
      }
      let ok = false;
      for (let i = 0; i < wdomains.length; i++) {
        const w = wdomains[i];
        let wParts = w.split('.');
        let parts = domain.split('.');
        if (wParts.length && wParts[0] === '*') {
          let bad = false;
          wParts = wParts.reverse();
          parts = parts.reverse();
          for (let p = 0; p < wParts.length - 1; p++) {
            if (wParts[p] !== parts[p]) {
              bad = true;
              break;
            }
          }
          ok = !bad;
        } else {
          let bad2 = false;
          if (wParts.length !== parts.length) {
            bad2 = true;
          }
          for (let p2 = 0; p2 < wParts.length; p2++) {
            if (wParts[p2] !== parts[p2]) {
              bad2 = true;
              break;
            }
          }
          ok = !bad2;
        }
        if (ok) {
          break;
        }
      }
      logger.debug(`isParentDomainWhitelisted : ${ok}`);
      return ok;
    });
  }
  function denyIfNotFromWhitelistedDomain(req, res, next) {
    const isWithinIframe = req.headers?.referrer?.includes('parent_url');
    const ref = req?.headers?.referrer;
    let refParts = [];
    let resultRef = '';
    if (isWithinIframe) {
      if (ref) {
        const decodedRefString = decodeURIComponent(ref.replace(/.*parent_url=/, '').replace(/&.*/, ''));
        if (decodedRefString?.length) refParts = decodedRefString.split('/');
        resultRef = (refParts && refParts.length >= 3 && refParts[2]) || '';
      }
    } else {
      if (ref?.length) refParts = ref.split('/');
      if (refParts && refParts.length >= 3) resultRef = refParts[2] || '';
    }
    const zid = req.p.zid;
    isParentDomainWhitelisted(resultRef, zid, isWithinIframe, req.p.domain_whitelist_override_key)
      .then((isOk) => {
        if (isOk) {
          next();
        } else {
          res.send(403, 'polis_err_domain');
          next('polis_err_domain');
        }
      })
      .catch((err) => {
        logger.error('error in isParentDomainWhitelisted', err);
        res.send(403, 'polis_err_domain');
        next('polis_err_domain_misc');
      });
  }
  function setDomainWhitelist(uid, newWhitelist) {
    return pgQueryP(
      'select * from site_domain_whitelist where site_id = (select site_id from users where uid = ($1));',
      [uid]
    ).then((rows) => {
      if (!rows || !rows.length) {
        return pgQueryP(
          'insert into site_domain_whitelist (site_id, domain_whitelist) values ((select site_id from users where uid = ($1)), $2);',
          [uid, newWhitelist]
        );
      }
      return pgQueryP(
        'update site_domain_whitelist set domain_whitelist = ($2) where site_id = (select site_id from users where uid = ($1));',
        [uid, newWhitelist]
      );
    });
  }
  function getDomainWhitelist(uid) {
    return pgQueryP(
      'select * from site_domain_whitelist where site_id = (select site_id from users where uid = ($1));',
      [uid]
    ).then((rows) => {
      if (!rows || !rows.length) {
        return '';
      }
      return rows[0].domain_whitelist;
    });
  }
  function handle_GET_domainWhitelist(req, res) {
    getDomainWhitelist(req.p.uid)
      .then((whitelist) => {
        res.json({
          domain_whitelist: whitelist
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_get_domainWhitelist_misc', err);
      });
  }
  function handle_POST_domainWhitelist(req, res) {
    setDomainWhitelist(req.p.uid, req.p.domain_whitelist)
      .then(() => {
        res.json({
          domain_whitelist: req.p.domain_whitelist
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_post_domainWhitelist_misc', err);
      });
  }
  function handle_GET_conversationStats(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const until = req.p.until;
    const hasPermission = req.p.rid ? Promise.resolve(!!req.p.rid) : isModerator(zid, uid);
    hasPermission
      .then((ok) => {
        if (!ok) {
          fail(res, 403, 'polis_err_conversationStats_need_report_id_or_moderation_permission');
          return;
        }
        const args = [zid];
        const q0 = until
          ? 'select created, pid, mod from comments where zid = ($1) and created < ($2) order by created;'
          : 'select created, pid, mod from comments where zid = ($1) order by created;';
        const q1 = until
          ? 'select created, pid from votes where zid = ($1) and created < ($2) order by created;'
          : 'select created, pid from votes where zid = ($1) order by created;';
        if (until) {
          args.push(until);
        }
        return Promise.all([pgQueryP_readOnly(q0, args), pgQueryP_readOnly(q1, args)]).then((a) => {
          function castTimestamp(o) {
            o.created = Number(o.created);
            return o;
          }
          const comments = _.map(a[0], castTimestamp);
          const votes = _.map(a[1], castTimestamp);
          const votesGroupedByPid = _.groupBy(votes, 'pid');
          const votesHistogramObj = {};
          _.each(votesGroupedByPid, (votesByParticipant, _pid) => {
            votesHistogramObj[votesByParticipant.length] = votesHistogramObj[votesByParticipant.length] + 1 || 1;
          });
          let votesHistogram = [];
          _.each(votesHistogramObj, (ptptCount, voteCount) => {
            votesHistogram.push({
              n_votes: voteCount,
              n_ptpts: ptptCount
            });
          });
          votesHistogram.sort((a, b) => a.n_ptpts - b.n_ptpts);
          const burstsForPid = {};
          const interBurstGap = 10 * 60 * 1000;
          _.each(votesGroupedByPid, (votesByParticipant, pid) => {
            burstsForPid[pid] = 1;
            let prevCreated = votesByParticipant.length ? votesByParticipant[0] : 0;
            for (let v = 1; v < votesByParticipant.length; v++) {
              const vote = votesByParticipant[v];
              if (interBurstGap + prevCreated < vote.created) {
                burstsForPid[pid] += 1;
              }
              prevCreated = vote.created;
            }
          });
          const burstHistogramObj = {};
          _.each(burstsForPid, (bursts, _pid) => {
            burstHistogramObj[bursts] = burstHistogramObj[bursts] + 1 || 1;
          });
          const burstHistogram = [];
          _.each(burstHistogramObj, (ptptCount, burstCount) => {
            burstHistogram.push({
              n_ptpts: ptptCount,
              n_bursts: Number(burstCount)
            });
          });
          burstHistogram.sort((a, b) => a.n_bursts - b.n_bursts);
          let actualParticipants = getFirstForPid(votes);
          actualParticipants = _.pluck(actualParticipants, 'created');
          let commenters = getFirstForPid(comments);
          commenters = _.pluck(commenters, 'created');
          const totalComments = _.pluck(comments, 'created');
          const totalVotes = _.pluck(votes, 'created');
          votesHistogram = _.map(votesHistogram, (x) => ({
            n_votes: Number(x.n_votes),
            n_ptpts: Number(x.n_ptpts)
          }));
          res.status(200).json({
            voteTimes: totalVotes,
            firstVoteTimes: actualParticipants,
            commentTimes: totalComments,
            firstCommentTimes: commenters,
            votesHistogram: votesHistogram,
            burstHistogram: burstHistogram
          });
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_conversationStats_misc', err);
      });
  }
  function handle_GET_snapshot(req, _res) {
    const _uid = req.p.uid;
    const _zid = req.p.zid;
    if (true) {
      throw new Error('TODO Needs to clone participants_extended and any other new tables as well.');
    }
  }
  function handle_GET_facebook_delete(req, res) {
    deleteFacebookUserRecord(req.p)
      .then(() => {
        res.json({});
      })
      .catch((err) => {
        fail(res, 500, err);
      });
  }
  function getFriends(fb_access_token) {
    function getMoreFriends(friendsSoFar, urlForNextCall) {
      return request
        .get(urlForNextCall)
        .then((response) => {
          const { data, paging } = response;
          if (data.length) {
            friendsSoFar.push(...data);
            if (paging.next) {
              return getMoreFriends(friendsSoFar, paging.next);
            }
          }
          return Promise.resolve(friendsSoFar);
        })
        .catch((_err) => {
          emailBadProblemTime('getMoreFriends failed');
          return Promise.resolve(friendsSoFar);
        });
    }
    return new Promise((resolve, reject) => {
      FB.setAccessToken(fb_access_token);
      FB.api('/me/friends', (response) => {
        if (response && !response.error) {
          const friendsSoFar = response.data;
          if (response.data.length && response.paging.next) {
            getMoreFriends(friendsSoFar, response.paging.next).then(resolve, reject);
          } else {
            resolve(friendsSoFar || []);
          }
        } else {
          reject(response);
        }
      });
    });
  }
  function getLocationInfo(fb_access_token, location) {
    return new Promise((resolve, _reject) => {
      if (location?.id) {
        FB.setAccessToken(fb_access_token);
        FB.api(`/${location.id}`, (locationResponse) => {
          resolve(locationResponse);
        });
      } else {
        resolve({});
      }
    });
  }
  function handle_POST_auth_facebook(req, res) {
    const response = JSON.parse(req?.p?.response || '');
    const fb_access_token = response?.authResponse?.accessToken;
    if (!fb_access_token) {
      emailBadProblemTime(`polis_err_missing_fb_access_token ${req?.headers?.referer}\n\n${req.p.response}`);
      fail(res, 500, 'polis_err_missing_fb_access_token');
      return;
    }
    const fields = [
      'email',
      'first_name',
      'friends',
      'gender',
      'id',
      'is_verified',
      'last_name',
      'link',
      'locale',
      'location',
      'name',
      'timezone',
      'updated_time',
      'verified'
    ];
    FB.setAccessToken(fb_access_token);
    FB.api(
      'me',
      {
        fields: fields
      },
      (fbRes) => {
        if (!fbRes || fbRes.error) {
          fail(res, 500, 'polis_err_fb_auth_check', fbRes?.error);
          return;
        }
        const friendsPromise = fbRes?.friends?.length ? getFriends(fb_access_token) : Promise.resolve([]);
        Promise.all([getLocationInfo(fb_access_token, fbRes.location), friendsPromise]).then((a) => {
          const locationResponse = a[0];
          const friends = a[1];
          if (locationResponse) {
            req.p.locationInfo = locationResponse;
          }
          if (friends) {
            req.p.fb_friends_response = JSON.stringify(friends);
          }
          response.locationInfo = locationResponse;
          do_handle_POST_auth_facebook(req, res, {
            locationInfo: locationResponse,
            friends: friends,
            info: _.pick(fbRes, fields)
          });
        });
      }
    );
  }
  function do_handle_POST_auth_facebook(req, res, o) {
    const TRUST_FB_TO_VALIDATE_EMAIL = true;
    const email = o.info.email;
    const hname = o.info.name;
    const fb_friends_response = o.friends;
    const fb_user_id = o.info.id;
    const response = JSON.parse(req?.p?.response || '');
    const fb_public_profile = o.info;
    const fb_login_status = response.status;
    const fb_access_token = response.authResponse.accessToken;
    const verified = o.info.verified;
    const _referrer = req?.cookies?.[COOKIES.REFERRER];
    const password = req.p.password;
    const uid = req.p.uid;
    const fbUserRecord = {
      fb_user_id: fb_user_id,
      fb_public_profile: fb_public_profile,
      fb_login_status: fb_login_status,
      fb_access_token: fb_access_token,
      fb_granted_scopes: req.p.fb_granted_scopes,
      fb_friends_response: req.p.fb_friends_response || '',
      response: req.p.response
    };
    function doFbUserHasAccountLinked(user) {
      if (user.fb_user_id === fb_user_id) {
        updateFacebookUserRecord(
          Object.assign(
            {},
            {
              uid: user.uid
            },
            fbUserRecord
          )
        )
          .then(
            () => {
              const friendsAddedPromise = fb_friends_response
                ? addFacebookFriends(user.uid, fb_friends_response)
                : Promise.resolve();
              return friendsAddedPromise.then(
                () => {
                  startSessionAndAddCookies(req, res, user.uid)
                    .then(() => {
                      res.json({
                        uid: user.uid,
                        hname: user.hname,
                        email: user.email
                      });
                    })
                    .catch((err) => {
                      fail(res, 500, 'polis_err_reg_fb_start_session2', err);
                    });
                },
                (err) => {
                  fail(res, 500, 'polis_err_linking_fb_friends2', err);
                }
              );
            },
            (err) => {
              fail(res, 500, 'polis_err_updating_fb_info', err);
            }
          )
          .catch((err) => {
            fail(res, 500, 'polis_err_fb_auth_misc', err);
          });
      } else {
        deleteFacebookUserRecord(user).then(
          () => {
            doFbNotLinkedButUserWithEmailExists(user);
          },
          (err) => {
            emailBadProblemTime(`facebook auth where user exists with different facebook account ${user.uid}`);
            fail(res, 500, 'polis_err_reg_fb_user_exists_with_different_account', err);
          }
        );
      }
    }
    function doFbNotLinkedButUserWithEmailExists(user) {
      if (!TRUST_FB_TO_VALIDATE_EMAIL && !password) {
        fail(res, 403, `polis_err_user_with_this_email_exists ${email}`);
      } else {
        const pwPromise = TRUST_FB_TO_VALIDATE_EMAIL ? Promise.resolve(true) : checkPassword(user.uid, password || '');
        pwPromise.then(
          (ok) => {
            if (ok) {
              createFacebookUserRecord(
                Object.assign(
                  {},
                  {
                    uid: user.uid
                  },
                  fbUserRecord
                )
              )
                .then(
                  () => {
                    const friendsAddedPromise = fb_friends_response
                      ? addFacebookFriends(user.uid, fb_friends_response)
                      : Promise.resolve();
                    return friendsAddedPromise
                      .then(
                        () => startSessionAndAddCookies(req, res, user.uid).then(() => user),
                        (err) => {
                          fail(res, 500, 'polis_err_linking_fb_friends', err);
                        }
                      )
                      .then(
                        (user) => {
                          res.status(200).json({
                            uid: user.uid,
                            hname: user.hname,
                            email: user.email
                          });
                        },
                        (err) => {
                          fail(res, 500, 'polis_err_linking_fb_misc', err);
                        }
                      );
                  },
                  (err) => {
                    fail(res, 500, 'polis_err_linking_fb_to_existing_polis_account', err);
                  }
                )
                .catch((err) => {
                  fail(res, 500, 'polis_err_linking_fb_to_existing_polis_account_misc', err);
                });
            } else {
              fail(res, 403, 'polis_err_password_mismatch');
            }
          },
          (err) => {
            fail(res, 500, 'polis_err_password_check', err);
          }
        );
      }
    }
    function doFbNoUserExistsYet(_user) {
      let promise;
      if (uid) {
        promise = Promise.all([
          pgQueryP('select * from users where uid = ($1);', [uid]),
          pgQueryP('update users set hname = ($2) where uid = ($1) and hname is NULL;', [uid, hname]),
          pgQueryP('update users set email = ($2) where uid = ($1) and email is NULL;', [uid, email])
        ]).then((o) => {
          const user = o[0][0];
          return user;
        });
      } else {
        const query = 'insert into users ' + '(email, hname) VALUES ' + '($1, $2) ' + 'returning *;';
        promise = pgQueryP(query, [email, hname]).then((rows) => {
          const user = (rows?.length && rows[0]) || null;
          return user;
        });
      }
      promise
        .then((user) => createFacebookUserRecord(Object.assign({}, user, fbUserRecord)).then(() => user))
        .then(
          (user) => {
            if (fb_friends_response) {
              return addFacebookFriends(user.uid, fb_friends_response).then(() => user);
            }
            return user;
          },
          (err) => {
            fail(res, 500, 'polis_err_reg_fb_user_creating_record2', err);
          }
        )
        .then(
          (user) => {
            const uid = user.uid;
            return startSessionAndAddCookies(req, res, uid).then(
              () => user,
              (err) => {
                fail(res, 500, 'polis_err_reg_fb_user_creating_record3', err);
              }
            );
          },
          (err) => {
            fail(res, 500, 'polis_err_reg_fb_user_creating_record', err);
          }
        )
        .then(
          (user) => {
            res.json({
              uid: user.uid,
              hname: user.hname,
              email: user.email
            });
          },
          (err) => {
            fail(res, 500, 'polis_err_reg_fb_user_misc22', err);
          }
        )
        .catch((err) => {
          fail(res, 500, 'polis_err_reg_fb_user_misc2', err);
        });
    }
    let emailVerifiedPromise = Promise.resolve(true);
    if (!verified) {
      if (email) {
        emailVerifiedPromise = isEmailVerified(email);
      } else {
        emailVerifiedPromise = Promise.resolve(false);
      }
    }
    Promise.all([emailVerifiedPromise]).then((a) => {
      const isVerifiedByPolisOrFacebook = a[0];
      if (!isVerifiedByPolisOrFacebook) {
        if (email) {
          doSendVerification(req, email);
          res.status(403).send('polis_err_reg_fb_verification_email_sent');
          return;
        }
        res.status(403).send('polis_err_reg_fb_verification_noemail_unverified');
        return;
      }
      pgQueryP(
        'select users.*, facebook_users.fb_user_id from users left join facebook_users on users.uid = facebook_users.uid ' +
          'where users.email = ($1) ' +
          '   or facebook_users.fb_user_id = ($2) ' +
          ';',
        [email, fb_user_id]
      )
        .then(
          (rows) => {
            let user = (rows?.length && rows[0]) || null;
            if (rows && rows.length > 1) {
              user = _.find(rows, (row) => row.fb_user_id === fb_user_id);
            }
            if (user) {
              if (user.fb_user_id) {
                doFbUserHasAccountLinked(user);
              } else {
                doFbNotLinkedButUserWithEmailExists(user);
              }
            } else {
              doFbNoUserExistsYet(user);
            }
          },
          (err) => {
            fail(res, 500, 'polis_err_reg_fb_user_looking_up_email', err);
          }
        )
        .catch((err) => {
          fail(res, 500, 'polis_err_reg_fb_user_misc', err);
        });
    });
  }
  function handle_POST_auth_new(req, res) {
    CreateUser.createUser(req, res);
  }
  function handle_POST_tutorial(req, res) {
    const uid = req.p.uid;
    const step = req.p.step;
    pgQueryP('update users set tut = ($1) where uid = ($2);', [step, uid])
      .then(() => {
        res.status(200).json({});
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_saving_tutorial_state', err);
      });
  }
  function handle_GET_users(req, res) {
    const uid = req.p.uid;
    if (req.p.errIfNoAuth && !uid) {
      fail(res, 401, 'polis_error_auth_needed');
      return;
    }
    getUser(uid, null, req.p.xid, req.p.owner_uid)
      .then(
        (user) => {
          res.status(200).json(user);
        },
        (err) => {
          fail(res, 500, 'polis_err_getting_user_info2', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_getting_user_info', err);
      });
  }
  const getUser = User.getUser;
  const getComments = Comment.getComments;
  const _getCommentsForModerationList = Comment._getCommentsForModerationList;
  const _getCommentsList = Comment._getCommentsList;
  const getNumberOfCommentsRemaining = Comment.getNumberOfCommentsRemaining;
  function handle_GET_participation(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const strict = req.p.strict;
    isOwner(zid, uid)
      .then((ok) => {
        if (!ok) {
          fail(res, 403, 'polis_err_get_participation_auth');
          return;
        }
        return Promise.all([
          pgQueryP_readOnly('select pid, count(*) from votes where zid = ($1) group by pid;', [zid]),
          pgQueryP_readOnly('select pid, count(*) from comments where zid = ($1) group by pid;', [zid]),
          getXids(zid)
        ]).then((o) => {
          const voteCountRows = o[0];
          const commentCountRows = o[1];
          const pidXidRows = o[2];
          let i;
          let r;
          if (strict && !pidXidRows.length) {
            fail(
              res,
              409,
              'polis_err_get_participation_missing_xids This conversation has no xids for its participants.'
            );
            return;
          }
          let result = new DD(() => ({
            votes: 0,
            comments: 0
          }));
          for (i = 0; i < voteCountRows.length; i++) {
            r = voteCountRows[i];
            result.g(r.pid).votes = Number(r.count);
          }
          for (i = 0; i < commentCountRows.length; i++) {
            r = commentCountRows[i];
            result.g(r.pid).comments = Number(r.count);
          }
          result = result.m;
          if (pidXidRows?.length) {
            const pidToXid = {};
            for (i = 0; i < pidXidRows.length; i++) {
              pidToXid[pidXidRows[i].pid] = pidXidRows[i].xid;
            }
            const xidBasedResult = {};
            let size = 0;
            _.each(result, (val, key) => {
              xidBasedResult[pidToXid[key]] = val;
              size += 1;
            });
            if (strict && (commentCountRows.length || voteCountRows.length) && size > 0) {
              fail(
                res,
                409,
                'polis_err_get_participation_missing_xids This conversation is missing xids for some of its participants.'
              );
              return;
            }
            res.status(200).json(xidBasedResult);
          } else {
            res.status(200).json(result);
          }
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_get_participation_misc', err);
      });
  }
  function getAgeRange(demo) {
    const currentYear = new Date().getUTCFullYear();
    const birthYear = demo.ms_birth_year_estimate_fb;
    if (_.isNull(birthYear) || _.isUndefined(birthYear) || _.isNaN(birthYear)) {
      return '?';
    }
    const age = currentYear - birthYear;
    if (age < 12) {
      return '0-11';
    }
    if (age < 18) {
      return '12-17';
    }
    if (age < 25) {
      return '18-24';
    }
    if (age < 35) {
      return '25-34';
    }
    if (age < 45) {
      return '35-44';
    }
    if (age < 55) {
      return '45-54';
    }
    if (age < 65) {
      return '55-64';
    }
    return '65+';
  }
  function getGender(demo) {
    let gender = demo.fb_gender;
    if (_.isNull(gender) || _.isUndefined(gender)) {
      gender = demo.ms_gender_estimate_fb;
    }
    return gender;
  }
  function getDemographicsForVotersOnComments(zid, comments) {
    function isAgree(v) {
      return v.vote === polisTypes.reactions.pull;
    }
    function isDisgree(v) {
      return v.vote === polisTypes.reactions.push;
    }
    function isPass(v) {
      return v.vote === polisTypes.reactions.pass;
    }
    function isGenderMale(demo) {
      return demo.gender === 0;
    }
    function isGenderFemale(demo) {
      return demo.gender === 1;
    }
    function isGenderUnknown(demo) {
      const gender = demo.gender;
      return gender !== 0 && gender !== 1;
    }
    return Promise.all([
      pgQueryP('select pid,tid,vote from votes_latest_unique where zid = ($1);', [zid]),
      pgQueryP(
        'select p.pid, d.* from participants p left join demographic_data d on p.uid = d.uid where p.zid = ($1);',
        [zid]
      )
    ]).then((a) => {
      let votes = a[0];
      let demo = a[1];
      demo = demo.map((d) => {
        return {
          pid: d.pid,
          gender: getGender(d),
          ageRange: getAgeRange(d)
        };
      });
      const demoByPid = _.indexBy(demo, 'pid');
      votes = votes.map((v) => {
        return _.extend(v, demoByPid[v.pid]);
      });
      const votesByTid = _.groupBy(votes, 'tid');
      return comments.map((c) => {
        const votesForThisComment = votesByTid[c.tid];
        if (!votesForThisComment || !votesForThisComment.length) {
          return c;
        }
        const agrees = votesForThisComment.filter(isAgree);
        const disagrees = votesForThisComment.filter(isDisgree);
        const passes = votesForThisComment.filter(isPass);
        const votesByAgeRange = _.groupBy(votesForThisComment, 'ageRange');
        c.demographics = {
          gender: {
            m: {
              agree: agrees.filter(isGenderMale).length,
              disagree: disagrees.filter(isGenderMale).length,
              pass: passes.filter(isGenderMale).length
            },
            f: {
              agree: agrees.filter(isGenderFemale).length,
              disagree: disagrees.filter(isGenderFemale).length,
              pass: passes.filter(isGenderFemale).length
            },
            '?': {
              agree: agrees.filter(isGenderUnknown).length,
              disagree: disagrees.filter(isGenderUnknown).length,
              pass: passes.filter(isGenderUnknown).length
            }
          },
          age: _.mapObject(votesByAgeRange, (votes, _ageRange) => {
            const o = _.countBy(votes, 'vote');
            return {
              agree: o[polisTypes.reactions.pull],
              disagree: o[polisTypes.reactions.push],
              pass: o[polisTypes.reactions.pass]
            };
          })
        };
        return c;
      });
    });
  }
  const translateAndStoreComment = Comment.translateAndStoreComment;
  function handle_GET_comments_translations(req, res) {
    const zid = req.p.zid;
    const tid = req.p.tid;
    const firstTwoCharsOfLang = req.p.lang.substr(0, 2);
    getComment(zid, tid)
      .then((comment) => {
        return dbPgQuery
          .queryP("select * from comment_translations where zid = ($1) and tid = ($2) and lang LIKE '$3%';", [
            zid,
            tid,
            firstTwoCharsOfLang
          ])
          .then((existingTranslations) => {
            if (existingTranslations) {
              return existingTranslations;
            }
            return translateAndStoreComment(zid, tid, comment.txt, req.p.lang);
          })
          .then((rows) => {
            res.status(200).json(rows || []);
          });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_get_comments_translations', err);
      });
  }
  function handle_GET_comments(req, res) {
    const rid = `${req?.headers?.['x-request-id']} ${req?.headers?.['user-agent']}`;
    logger.debug('getComments begin', { rid });
    const isReportQuery = !_.isUndefined(req.p.rid);
    getComments(req.p)
      .then((comments) => {
        if (req.p.rid) {
          return pgQueryP('select tid, selection from report_comment_selections where rid = ($1);', [req.p.rid]).then(
            (selections) => {
              const tidToSelection = _.indexBy(selections, 'tid');
              comments = comments.map((c) => {
                c.includeInReport = tidToSelection[c.tid] && tidToSelection[c.tid].selection > 0;
                return c;
              });
              return comments;
            }
          );
        }
        return comments;
      })
      .then((comments) => {
        comments = comments.map((c) => {
          const hasTwitter = c.social?.twitter_user_id;
          if (hasTwitter) {
            c.social.twitter_profile_image_url_https = `${getServerNameWithProtocol(req)}/twitter_image?id=${c.social.twitter_user_id}`;
          }
          const hasFacebook = c.social?.fb_user_id;
          if (hasFacebook) {
            const width = 40;
            const height = 40;
            c.social.fb_picture = `https://graph.facebook.com/v2.2/${c.social.fb_user_id}/picture?width=${width}&height=${height}`;
          }
          return c;
        });
        if (req.p.include_demographics) {
          isModerator(req.p.zid, req.p.uid)
            .then((owner) => {
              if (owner || isReportQuery) {
                return getDemographicsForVotersOnComments(req.p.zid, comments)
                  .then((commentsWithDemographics) => {
                    finishArray(res, commentsWithDemographics);
                  })
                  .catch((err) => {
                    fail(res, 500, 'polis_err_get_comments3', err);
                  });
              }
              fail(res, 500, 'polis_err_get_comments_permissions');
            })
            .catch((err) => {
              fail(res, 500, 'polis_err_get_comments2', err);
            });
        } else {
          finishArray(res, comments);
        }
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_get_comments', err);
      });
  }
  function isDuplicateKey(err) {
    const isdup =
      err.code === 23505 ||
      err.code === '23505' ||
      err.sqlState === 23505 ||
      err.sqlState === '23505' ||
      err.messagePrimary?.includes('duplicate key value');
    return isdup;
  }
  function failWithRetryRequest(res) {
    res.setHeader('Retry-After', 0);
    logger.warn('failWithRetryRequest');
    res.writeHead(500).send(57493875);
  }
  function getNumberOfCommentsWithModerationStatus(zid, mod) {
    return new MPromise('getNumberOfCommentsWithModerationStatus', (resolve, reject) => {
      pgQuery_readOnly('select count(*) from comments where zid = ($1) and mod = ($2);', [zid, mod], (err, result) => {
        if (err) {
          reject(err);
        } else {
          let count = result?.rows?.[0]?.count;
          count = Number(count);
          if (Number.isNaN(count)) {
            count = void 0;
          }
          resolve(count);
        }
      });
    });
  }
  function sendCommentModerationEmail(_req, uid, zid, unmoderatedCommentCount) {
    if (_.isUndefined(unmoderatedCommentCount)) {
      unmoderatedCommentCount = '';
    }
    let body = unmoderatedCommentCount;
    if (unmoderatedCommentCount === 1) {
      body += ' Statement is waiting for your review here: ';
    } else {
      body += ' Statements are waiting for your review here: ';
    }
    getZinvite(zid)
      .catch((err) => {
        logger.error('polis_err_getting_zinvite', err);
        return void 0;
      })
      .then((zinvite) => {
        body += createProdModerationUrl(zinvite);
        body += '\n\nThank you for using Polis.';
        return sendEmailByUid(uid, `Waiting for review (conversation ${zinvite})`, body);
      })
      .catch((err) => {
        logger.error('polis_err_sending_email', err);
      });
  }
  function createProdModerationUrl(zinvite) {
    return `https://pol.is/m/${zinvite}`;
  }
  function createModerationUrl(req, zinvite) {
    let server = Config.getServerUrl();
    if (domainOverride) {
      server = `${req?.protocol}://${domainOverride}`;
    }
    if (req?.headers?.host?.includes('preprod.pol.is')) {
      server = 'https://preprod.pol.is';
    }
    const url = `${server}/m/${zinvite}`;
    return url;
  }
  function moderateComment(zid, tid, active, mod, is_meta) {
    return new Promise((resolve, reject) => {
      const query = 'UPDATE comments SET active = $1, mod = $2, is_meta = $3 WHERE zid = $4 AND tid = $5';
      const params = [active, mod, is_meta, zid, tid];
      logger.debug('Executing query:', { query });
      logger.debug('With parameters:', { params });
      pgQuery(query, params, (err, result) => {
        if (err) {
          logger.error('moderateComment pgQuery error:', err);
          reject(err);
        } else {
          logger.debug('moderateComment pgQuery executed successfully');
          resolve(result);
        }
      });
    });
  }
  const getComment = Comment.getComment;
  function hasBadWords(txt) {
    txt = txt.toLowerCase();
    const tokens = txt.split(' ');
    for (let i = 0; i < tokens.length; i++) {
      if (badwords[tokens[i]]) {
        return true;
      }
    }
    return false;
  }
  function commentExists(zid, txt) {
    return pgQueryP('select zid from comments where zid = ($1) and txt = ($2);', [zid, txt]).then(
      (rows) => rows?.length
    );
  }
  const GOOGLE_DISCOVERY_URL = 'https://commentanalyzer.googleapis.com/$discovery/rest?version=v1alpha1';
  async function analyzeComment(txt) {
    try {
      const client = await google.discoverAPI(GOOGLE_DISCOVERY_URL);
      const analyzeRequest = {
        comment: {
          text: txt
        },
        requestedAttributes: {
          TOXICITY: {}
        }
      };
      const response = await client.comments.analyze({
        key: Config.googleJigsawPerspectiveApiKey,
        resource: analyzeRequest
      });
      return response.data;
    } catch (err) {
      logger.error('analyzeComment error', err);
    }
  }
  async function handle_POST_comments(req, res) {
    let { zid, xid, uid, txt, pid: initialPid, vote, anon, is_seed } = req.p;
    let pid = initialPid;
    let currentPid = pid;
    const mustBeModerator = anon;
    if (!txt || txt === '') {
      fail(res, 400, 'polis_err_param_missing_txt');
      return;
    }
    async function doGetPid() {
      if (_.isUndefined(pid)) {
        const newPid = await getPidPromise(zid, uid, true);
        if (newPid === -1) {
          const rows = await addParticipant(zid, uid);
          const ptpt = rows[0];
          pid = ptpt.pid;
          currentPid = pid;
          return Number(pid);
        }
        return newPid;
      }
      return Number(pid);
    }
    try {
      logger.debug('Post comments txt', { zid, pid, txt });
      const ip =
        req.headers['x-forwarded-for'] ||
        req.connection?.remoteAddress ||
        req.socket?.remoteAddress ||
        req.connection?.socket?.remoteAddress;
      const isSpamPromise = isSpam({
        comment_content: txt,
        comment_author: uid,
        permalink: `https://pol.is/${zid}`,
        user_ip: ip,
        user_agent: req.headers['user-agent'],
        referrer: req.headers.referer
      }).catch((err) => {
        logger.error('isSpam failed', err);
        return false;
      });
      const jigsawModerationPromise = Config.googleJigsawPerspectiveApiKey
        ? analyzeComment(txt)
        : Promise.resolve(null);
      const isModeratorPromise = isModerator(zid, uid);
      const conversationInfoPromise = getConversationInfo(zid);
      let shouldCreateXidRecord = false;
      const pidPromise = (async () => {
        if (xid) {
          const xidUser = await getXidStuff(xid, zid);
          shouldCreateXidRecord = xidUser === 'noXidRecord';
          if (typeof xidUser === 'object') {
            uid = xidUser.uid;
            pid = xidUser.pid;
            return pid;
          }
        }
        const newPid = await doGetPid();
        if (shouldCreateXidRecord) {
          await createXidRecordByZid(zid, uid, xid, null, null, null);
        }
        return newPid;
      })();
      const commentExistsPromise = commentExists(zid, txt);
      const [finalPid, conv, is_moderator, commentExistsAlready, spammy, jigsawResponse] = await Promise.all([
        pidPromise,
        conversationInfoPromise,
        isModeratorPromise,
        commentExistsPromise,
        isSpamPromise,
        jigsawModerationPromise
      ]);
      if (!is_moderator && mustBeModerator) {
        fail(res, 403, 'polis_err_post_comment_auth');
        return;
      }
      if (finalPid && finalPid < 0) {
        fail(res, 500, 'polis_err_post_comment_bad_pid');
        return;
      }
      if (commentExistsAlready) {
        fail(res, 409, 'polis_err_post_comment_duplicate');
        return;
      }
      if (!conv.is_active) {
        fail(res, 403, 'polis_err_conversation_is_closed');
        return;
      }
      const bad = hasBadWords(txt);
      const velocity = 1;
      const jigsawToxicityThreshold = 0.8;
      let active = true;
      const classifications = [];
      const toxicityScore = jigsawResponse?.attributeScores?.TOXICITY?.summaryScore?.value;
      if (typeof toxicityScore === 'number' && !Number.isNaN(toxicityScore)) {
        logger.debug(`Jigsaw toxicity Score for comment "${txt}": ${toxicityScore}`);
        if (toxicityScore > jigsawToxicityThreshold && conv.profanity_filter) {
          active = false;
          classifications.push('bad');
          logger.info('active=false because (jigsawToxicity && conv.profanity_filter)');
        }
      } else if (bad && conv.profanity_filter) {
        active = false;
        classifications.push('bad');
        logger.info('active=false because (bad && conv.profanity_filter)');
      }
      if (spammy && conv.spam_filter) {
        active = false;
        classifications.push('spammy');
        logger.info('active=false because (spammy && conv.spam_filter)');
      }
      if (spammy && conv.spam_filter) {
        active = false;
        classifications.push('spammy');
        logger.info('active=false because (spammy && conv.spam_filter)');
      }
      if (conv.strict_moderation) {
        active = false;
        logger.info('active=false because (conv.strict_moderation)');
      }
      let mod = 0;
      if (is_moderator && is_seed) {
        mod = polisTypes.mod.ok;
        active = true;
      }
      const [detections] = await Promise.all([detectLanguage(txt)]);
      const detection = Array.isArray(detections) ? detections[0] : detections;
      const lang = detection.language;
      const lang_confidence = detection.confidence;
      const insertedComment = await pgQueryP(
        `INSERT INTO COMMENTS
        (pid, zid, txt, velocity, active, mod, uid, anon, is_seed, created, tid, lang, lang_confidence)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, default, null, $10, $11)
        RETURNING *;`,
        [finalPid, zid, txt, velocity, active, mod, uid, anon || false, is_seed || false, lang, lang_confidence]
      );
      const comment = insertedComment[0];
      const tid = comment.tid;
      if (bad || spammy || conv.strict_moderation) {
        try {
          const n = await getNumberOfCommentsWithModerationStatus(zid, polisTypes.mod.unmoderated);
          if (n !== 0) {
            const users = await pgQueryP_readOnly(
              'SELECT * FROM users WHERE site_id = (SELECT site_id FROM page_ids WHERE zid = $1) UNION SELECT * FROM users WHERE uid = $2;',
              [zid, conv.owner]
            );
            const uids = users.map((user) => user.uid);
            uids.forEach((uid) => sendCommentModerationEmail(req, Number(uid), zid, n));
          }
        } catch (err) {
          logger.error('polis_err_getting_modstatus_comment_count', err);
        }
      } else {
        addNotificationTask(zid);
      }
      if (is_seed && _.isUndefined(vote) && Number(zid) <= 17037) {
        vote = 0;
      }
      let createdTime = comment.created;
      if (!_.isUndefined(vote)) {
        try {
          const voteResult = await votesPost(uid, finalPid, zid, tid, xid, vote, 0);
          if (voteResult?.vote?.created) {
            createdTime = voteResult.vote.created;
          }
        } catch (err) {
          fail(res, 500, 'polis_err_vote_on_create', err);
          return;
        }
      }
      setTimeout(() => {
        updateConversationModifiedTime(zid, createdTime);
        updateLastInteractionTimeForConversation(zid, uid);
        if (!_.isUndefined(vote)) {
          updateVoteCount(zid, finalPid);
        }
      }, 100);
      res.json({
        tid: tid,
        currentPid: currentPid
      });
    } catch (err) {
      if (err.code === '23505' || err.code === 23505) {
        fail(res, 409, 'polis_err_post_comment_duplicate', err);
      } else {
        fail(res, 500, 'polis_err_post_comment', err);
      }
    }
  }
  function handle_GET_votes_me(req, res) {
    getPid(req.p.zid, req.p.uid, (err, pid) => {
      if (err || pid < 0) {
        fail(res, 500, 'polis_err_getting_pid', err);
        return;
      }
      pgQuery_readOnly('SELECT * FROM votes WHERE zid = ($1) AND pid = ($2);', [req.p.zid, req.p.pid], (err, docs) => {
        if (err) {
          fail(res, 500, 'polis_err_get_votes_by_me', err);
          return;
        }
        for (let i = 0; i < docs.rows.length; i++) {
          docs.rows[i].weight = docs.rows[i].weight / 32767;
        }
        finishArray(res, docs.rows);
      });
    });
  }
  function handle_GET_votes(req, res) {
    getVotesForSingleParticipant(req.p).then(
      (votes) => {
        finishArray(res, votes);
      },
      (err) => {
        fail(res, 500, 'polis_err_votes_get', err);
      }
    );
  }
  function selectProbabilistically(comments, priorities, _nTotal, _nRemaining) {
    const lookup = _.reduce(
      comments,
      (o, comment) => {
        const lookup_val = o.lastCount + (priorities[comment.tid] || 1);
        o.lookup.push([lookup_val, comment]);
        o.lastCount = lookup_val;
        return o;
      },
      { lastCount: 0, lookup: [] }
    );
    const randomN = Math.random() * lookup.lastCount;
    const result = _.find(lookup.lookup, (x) => x[0] > randomN);
    const c = result?.[1];
    c.randomN = randomN;
    return c;
  }
  function getNextPrioritizedComment(zid, pid, withoutTids, include_social) {
    const params = {
      zid: zid,
      not_voted_by_pid: pid,
      include_social: include_social
    };
    if (!_.isUndefined(withoutTids) && withoutTids.length) {
      params.withoutTids = withoutTids;
    }
    return Promise.all([getComments(params), getPca(zid, 0), getNumberOfCommentsRemaining(zid, pid)]).then(
      (results) => {
        const comments = results[0];
        const math = results[1];
        const numberOfCommentsRemainingRows = results[2];
        logger.debug('getNextPrioritizedComment intermediate results:', {
          zid,
          pid,
          numberOfCommentsRemainingRows
        });
        if (!comments || !comments.length) {
          return null;
        }
        if (!numberOfCommentsRemainingRows || !numberOfCommentsRemainingRows.length) {
          throw new Error(`polis_err_getNumberOfCommentsRemaining_${zid}_${pid}`);
        }
        const commentPriorities = math ? math.asPOJO['comment-priorities'] || {} : {};
        const nTotal = Number(numberOfCommentsRemainingRows[0].total);
        const nRemaining = Number(numberOfCommentsRemainingRows[0].remaining);
        const c = selectProbabilistically(comments, commentPriorities, nTotal, nRemaining);
        c.remaining = nRemaining;
        c.total = nTotal;
        return c;
      }
    );
  }
  function getCommentTranslations(zid, tid) {
    return dbPgQuery.queryP('select * from comment_translations where zid = ($1) and tid = ($2);', [zid, tid]);
  }
  function getNextComment(zid, pid, withoutTids, include_social, lang) {
    return getNextPrioritizedComment(zid, pid, withoutTids, include_social).then((c) => {
      if (lang && c) {
        const firstTwoCharsOfLang = lang.substr(0, 2);
        return getCommentTranslations(zid, c.tid).then((translations) => {
          c.translations = translations;
          const hasMatch = _.some(translations, (t) => {
            return t.lang.startsWith(firstTwoCharsOfLang);
          });
          if (!hasMatch) {
            return translateAndStoreComment(zid, c.tid, c.txt, lang).then((translation) => {
              if (translation) {
                c.translations.push(translation);
              }
              return c;
            });
          }
          return c;
        });
      }
      if (c) {
        c.translations = [];
      }
      return c;
    });
  }
  function addNoMoreCommentsRecord(zid, pid) {
    return pgQueryP(
      'insert into event_ptpt_no_more_comments (zid, pid, votes_placed) values ($1, $2, ' +
        '(select count(*) from votes where zid = ($1) and pid = ($2)))',
      [zid, pid]
    );
  }
  function handle_GET_nextComment(req, res) {
    if (req.timedout) {
      return;
    }
    getNextComment(req.p.zid, req.p.not_voted_by_pid, req.p.without, req.p.include_social, req.p.lang)
      .then(
        (c) => {
          if (req.timedout) {
            return;
          }
          if (c) {
            if (!_.isUndefined(req.p.not_voted_by_pid)) {
              c.currentPid = req.p.not_voted_by_pid;
            }
            finishOne(res, c);
          } else {
            const o = {};
            if (!_.isUndefined(req.p.not_voted_by_pid)) {
              o.currentPid = req.p.not_voted_by_pid;
            }
            res.status(200).json(o);
          }
        },
        (err) => {
          if (req.timedout) {
            return;
          }
          fail(res, 500, 'polis_err_get_next_comment2', err);
        }
      )
      .catch((err) => {
        if (req.timedout) {
          return;
        }
        fail(res, 500, 'polis_err_get_next_comment', err);
      });
  }
  function handle_GET_participationInit(req, res) {
    logger.info('handle_GET_participationInit');
    function ifConv(f, args) {
      if (req.p.conversation_id) {
        return f.apply(null, args);
      }
      return Promise.resolve(null);
    }
    function ifConvAndAuth(f, args) {
      if (req.p.uid) {
        return ifConv(f, args);
      }
      return Promise.resolve(null);
    }
    const acceptLanguage = req?.headers?.['accept-language'] || req?.headers?.['Accept-Language'] || 'en-US';
    if (req.p.lang === 'acceptLang') {
      req.p.lang = acceptLanguage.substr(0, 2);
    }
    getPermanentCookieAndEnsureItIsSet(req, res);
    Promise.all([
      getUser(req.p.uid, req.p.zid, req.p.xid, req.p.owner_uid),
      ifConvAndAuth(getParticipant, [req.p.zid, req.p.uid]),
      ifConv(getNextComment, [req.p.zid, req.p.pid, [], true, req.p.lang]),
      ifConv(getOneConversation, [req.p.zid, req.p.uid, req.p.lang]),
      ifConv(getVotesForSingleParticipant, [req.p]),
      ifConv(getPca, [req.p.zid, -1]),
      ifConv(doFamousQuery, [req.p, req])
    ])
      .then(
        (arr) => {
          const conv = arr[3];
          const o = {
            user: arr[0],
            ptpt: arr[1],
            nextComment: arr[2],
            conversation: conv,
            votes: arr[4] || [],
            pca: arr[5] ? (arr[5].asJSON ? arr[5].asJSON : null) : null,
            famous: arr[6],
            acceptLanguage: acceptLanguage
          };
          if (o.conversation) {
            o.conversation.zid = undefined;
            o.conversation.conversation_id = req.p.conversation_id;
          }
          if (o.ptpt) {
            o.ptpt.zid = undefined;
          }
          for (let i = 0; i < o.votes.length; i++) {
            o.votes[i].zid = undefined;
          }
          if (!o.nextComment) {
            o.nextComment = {};
          }
          if (!_.isUndefined(req.p.pid)) {
            o.nextComment.currentPid = req.p.pid;
          }
          res.status(200).json(o);
        },
        (err) => {
          fail(res, 500, 'polis_err_get_participationInit2', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_get_participationInit', err);
      });
  }
  function updateConversationModifiedTime(zid, t) {
    const modified = _.isUndefined(t) ? Date.now() : Number(t);
    let query = 'update conversations set modified = ($2) where zid = ($1) and modified < ($2);';
    let params = [zid, modified];
    if (_.isUndefined(t)) {
      query = 'update conversations set modified = now_as_millis() where zid = ($1);';
      params = [zid];
    }
    return pgQueryP(query, params);
  }
  const createXidRecordByZid = Conversation.createXidRecordByZid;
  const getXidStuff = User.getXidStuff;
  function handle_PUT_participants_extended(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const fields = {};
    if (!_.isUndefined(req.p.show_translation_activated)) {
      fields.show_translation_activated = req.p.show_translation_activated;
    }
    const q = sql_participants_extended
      .update(fields)
      .where(sql_participants_extended.zid.equals(zid))
      .and(sql_participants_extended.uid.equals(uid));
    pgQueryP(q.toString(), [])
      .then((result) => {
        res.json(result);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_put_participants_extended', err);
      });
  }
  function handle_POST_votes(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    let pid = req.p.pid;
    const lang = req.p.lang;
    const token = req.cookies[COOKIES.TOKEN];
    const apiToken = req?.headers?.authorization || '';
    const xPolisHeaderToken = req?.headers?.['x-polis'];
    if (!uid && !token && !apiToken && !xPolisHeaderToken) {
      fail(res, 403, 'polis_err_vote_noauth');
      return;
    }
    const permanent_cookie = getPermanentCookieAndEnsureItIsSet(req, res);
    const pidReadyPromise = _.isUndefined(req.p.pid)
      ? addParticipantAndMetadata(req.p.zid, req.p.uid, req, permanent_cookie).then((rows) => {
          const ptpt = rows[0];
          pid = ptpt.pid;
        })
      : Promise.resolve();
    pidReadyPromise
      .then(() => {
        let vote;
        const pidReadyPromise = _.isUndefined(pid)
          ? addParticipant(zid, uid).then((rows) => {
              const ptpt = rows[0];
              pid = ptpt.pid;
            })
          : Promise.resolve();
        return pidReadyPromise
          .then(() => votesPost(uid, pid, zid, req.p.tid, req.p.xid, req.p.vote, req.p.weight))
          .then((o) => {
            vote = o.vote;
            const createdTime = vote.created;
            setTimeout(() => {
              updateConversationModifiedTime(zid, createdTime);
              updateLastInteractionTimeForConversation(zid, uid);
              updateVoteCount(zid, pid);
            }, 100);
            if (_.isUndefined(req.p.starred)) {
              return;
            }
            return addStar(zid, req.p.tid, pid, req.p.starred, createdTime);
          })
          .then(() => getNextComment(zid, pid, [], true, lang))
          .then((nextComment) => {
            logger.debug('handle_POST_votes nextComment:', {
              zid,
              pid,
              nextComment
            });
            const result = {};
            if (nextComment) {
              result.nextComment = nextComment;
            } else {
              addNoMoreCommentsRecord(zid, pid);
            }
            result.currentPid = pid;
            if (result.shouldMod) {
              result.modOptions = {};
              if (req.p.vote === polisTypes.reactions.pull) {
                result.modOptions.as_important = true;
                result.modOptions.as_factual = true;
                result.modOptions.as_feeling = true;
              } else if (req.p.vote === polisTypes.reactions.push) {
                result.modOptions.as_notmyfeeling = true;
                result.modOptions.as_notgoodidea = true;
                result.modOptions.as_notfact = true;
                result.modOptions.as_abusive = true;
              } else if (req.p.vote === polisTypes.reactions.pass) {
                result.modOptions.as_unsure = true;
                result.modOptions.as_spam = true;
                result.modOptions.as_abusive = true;
              }
            }
            finishOne(res, result);
          });
      })
      .catch((err) => {
        if (err === 'polis_err_vote_duplicate') {
          fail(res, 406, 'polis_err_vote_duplicate', err);
        } else if (err === 'polis_err_conversation_is_closed') {
          fail(res, 403, 'polis_err_conversation_is_closed', err);
        } else if (err === 'polis_err_post_votes_social_needed') {
          fail(res, 403, 'polis_err_post_votes_social_needed', err);
        } else if (err === 'polis_err_xid_not_whitelisted') {
          fail(res, 403, 'polis_err_xid_not_whitelisted', err);
        } else {
          fail(res, 500, 'polis_err_vote', err);
        }
      });
  }
  function handle_POST_ptptCommentMod(req, res) {
    const zid = req.p.zid;
    const pid = req.p.pid;
    const uid = req.p.uid;
    return pgQueryP(
      'insert into crowd_mod (' +
        'zid, ' +
        'pid, ' +
        'tid, ' +
        'as_abusive, ' +
        'as_factual, ' +
        'as_feeling, ' +
        'as_important, ' +
        'as_notfact, ' +
        'as_notgoodidea, ' +
        'as_notmyfeeling, ' +
        'as_offtopic, ' +
        'as_spam, ' +
        'as_unsure) values (' +
        '$1, ' +
        '$2, ' +
        '$3, ' +
        '$4, ' +
        '$5, ' +
        '$6, ' +
        '$7, ' +
        '$8, ' +
        '$9, ' +
        '$10, ' +
        '$11, ' +
        '$12, ' +
        '$13);',
      [
        req.p.zid,
        req.p.pid,
        req.p.tid,
        req.p.as_abusive,
        req.p.as_factual,
        req.p.as_feeling,
        req.p.as_important,
        req.p.as_notfact,
        req.p.as_notgoodidea,
        req.p.as_notmyfeeling,
        req.p.as_offtopic,
        req.p.as_spam,
        req.p.unsure
      ]
    )
      .then((createdTime) => {
        setTimeout(() => {
          updateConversationModifiedTime(req.p.zid, createdTime);
          updateLastInteractionTimeForConversation(zid, uid);
        }, 100);
      })
      .then(() => getNextComment(req.p.zid, pid, [], true, req.p.lang))
      .then((nextComment) => {
        const result = {};
        if (nextComment) {
          result.nextComment = nextComment;
        } else {
          addNoMoreCommentsRecord(req.p.zid, pid);
        }
        result.currentPid = req.p.pid;
        finishOne(res, result);
      })
      .catch((err) => {
        if (err === 'polis_err_ptptCommentMod_duplicate') {
          fail(res, 406, 'polis_err_ptptCommentMod_duplicate', err);
        } else if (err === 'polis_err_conversation_is_closed') {
          fail(res, 403, 'polis_err_conversation_is_closed', err);
        } else {
          fail(res, 500, 'polis_err_ptptCommentMod', err);
        }
      });
  }
  function handle_POST_upvotes(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    pgQueryP('select * from upvotes where uid = ($1) and zid = ($2);', [uid, zid]).then(
      (rows) => {
        if (rows?.length) {
          fail(res, 403, 'polis_err_upvote_already_upvoted');
        } else {
          pgQueryP('insert into upvotes (uid, zid) VALUES ($1, $2);', [uid, zid]).then(
            () => {
              pgQueryP(
                'update conversations set upvotes = (select count(*) from upvotes where zid = ($1)) where zid = ($1);',
                [zid]
              ).then(
                () => {
                  res.status(200).json({});
                },
                (err) => {
                  fail(res, 500, 'polis_err_upvote_update', err);
                }
              );
            },
            (err) => {
              fail(res, 500, 'polis_err_upvote_insert', err);
            }
          );
        }
      },
      (err) => {
        fail(res, 500, 'polis_err_upvote_check', err);
      }
    );
  }
  function addStar(zid, tid, pid, starred, created) {
    starred = starred ? 1 : 0;
    let query =
      'INSERT INTO stars (pid, zid, tid, starred, created) VALUES ($1, $2, $3, $4, default) RETURNING created;';
    const params = [pid, zid, tid, starred];
    if (!_.isUndefined(created)) {
      query = 'INSERT INTO stars (pid, zid, tid, starred, created) VALUES ($1, $2, $3, $4, $5) RETURNING created;';
      params.push(created);
    }
    return pgQueryP(query, params);
  }
  function handle_POST_stars(req, res) {
    addStar(req.p.zid, req.p.tid, req.p.pid, req.p.starred)
      .then((result) => {
        const createdTime = result.rows[0].created;
        setTimeout(() => {
          updateConversationModifiedTime(req.p.zid, createdTime);
        }, 100);
        res.status(200).json({});
      })
      .catch((err) => {
        if (err) {
          if (isDuplicateKey(err)) {
            fail(res, 406, 'polis_err_vote_duplicate', err);
          } else {
            fail(res, 500, 'polis_err_vote', err);
          }
        }
      });
  }
  function handle_POST_trashes(req, res) {
    const query = 'INSERT INTO trashes (pid, zid, tid, trashed, created) VALUES ($1, $2, $3, $4, default);';
    const params = [req.p.pid, req.p.zid, req.p.tid, req.p.trashed];
    pgQuery(query, params, (err, result) => {
      if (err) {
        if (isDuplicateKey(err)) {
          fail(res, 406, 'polis_err_vote_duplicate', err);
        } else {
          fail(res, 500, 'polis_err_vote', err);
        }
        return;
      }
      const createdTime = result.rows[0].created;
      setTimeout(() => {
        updateConversationModifiedTime(req.p.zid, createdTime);
      }, 100);
      res.status(200).json({});
    });
  }
  function verifyMetadataAnswersExistForEachQuestion(zid) {
    const errorcode = 'polis_err_missing_metadata_answers';
    return new Promise((resolve, reject) => {
      pgQuery_readOnly('select pmqid from participant_metadata_questions where zid = ($1);', [zid], (err, results) => {
        if (err) {
          reject(err);
          return;
        }
        if (!results.rows || !results.rows.length) {
          resolve();
          return;
        }
        const pmqids = results.rows.map((row) => Number(row.pmqid));
        pgQuery_readOnly(
          `select pmaid, pmqid from participant_metadata_answers where pmqid in (${pmqids.join(',')}) and alive = TRUE and zid = ($1);`,
          [zid],
          (err, results) => {
            if (err) {
              reject(err);
              return;
            }
            if (!results.rows || !results.rows.length) {
              reject(new Error(errorcode));
              return;
            }
            const questions = _.reduce(
              pmqids,
              (o, pmqid) => {
                o[pmqid] = 1;
                return o;
              },
              {}
            );
            results.rows.forEach((row) => {
              delete questions[row.pmqid];
            });
            if (Object.keys(questions).length) {
              reject(new Error(errorcode));
            } else {
              resolve();
            }
          }
        );
      });
    });
  }
  function handle_PUT_comments(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    const tid = req.p.tid;
    const active = req.p.active;
    const mod = req.p.mod;
    const is_meta = req.p.is_meta;
    logger.debug(`Attempting to update comment. zid: ${zid}, tid: ${tid}, uid: ${uid}`);
    isModerator(zid, uid)
      .then((isModerator) => {
        logger.debug(`isModerator result: ${isModerator}`);
        if (isModerator) {
          moderateComment(zid, tid, active, mod, is_meta).then(
            () => {
              logger.debug('Comment moderated successfully');
              res.status(200).json({});
            },
            (err) => {
              logger.error('Error in moderateComment:', err);
              fail(res, 500, 'polis_err_update_comment', err);
            }
          );
        } else {
          logger.debug('User is not a moderator');
          fail(res, 403, 'polis_err_update_comment_auth');
        }
      })
      .catch((err) => {
        logger.error('Error in isModerator:', err);
        fail(res, 500, 'polis_err_update_comment', err);
      });
  }
  function handle_POST_reportCommentSelections(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    const rid = req.p.rid;
    const tid = req.p.tid;
    const selection = req.p.include ? 1 : -1;
    isModerator(zid, uid)
      .then((isMod) => {
        if (!isMod) {
          return fail(res, 403, 'polis_err_POST_reportCommentSelections_auth');
        }
        return pgQueryP(
          'insert into report_comment_selections (rid, tid, selection, zid, modified) values ($1, $2, $3, $4, now_as_millis()) ' +
            'on conflict (rid, tid) do update set selection = ($3), zid  = ($4), modified = now_as_millis();',
          [rid, tid, selection, zid]
        )
          .then(() => {
            return pgQueryP('delete from math_report_correlationmatrix where rid = ($1);', [rid]);
          })
          .then(() => {
            res.json({});
          });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_POST_reportCommentSelections_misc', err);
      });
  }
  function generateAndReplaceZinvite(zid, generateShortZinvite) {
    let len = 12;
    if (generateShortZinvite) {
      len = 6;
    }
    return new Promise((resolve, reject) => {
      generateToken(len, false, (err, zinvite) => {
        if (err) {
          return reject('polis_err_creating_zinvite');
        }
        pgQuery('update zinvites set zinvite = ($1) where zid = ($2);', [zinvite, zid], (err, _results) => {
          if (err) {
            reject(err);
          } else {
            resolve(zinvite);
          }
        });
      });
    });
  }
  function handle_POST_conversation_close(req, res) {
    let q = 'select * from conversations where zid = ($1)';
    const params = [req.p.zid];
    if (!isPolisDev(req.p.uid)) {
      q = `${q} and owner = ($2)`;
      params.push(req.p.uid);
    }
    pgQueryP(q, params)
      .then((rows) => {
        if (!rows || !rows.length) {
          fail(res, 500, 'polis_err_closing_conversation_no_such_conversation');
          return;
        }
        const conv = rows[0];
        pgQueryP('update conversations set is_active = false where zid = ($1);', [conv.zid]);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_closing_conversation', err);
      });
  }
  function handle_POST_conversation_reopen(req, res) {
    let q = 'select * from conversations where zid = ($1)';
    const params = [req.p.zid];
    if (!isPolisDev(req.p.uid)) {
      q = `${q} and owner = ($2)`;
      params.push(req.p.uid);
    }
    pgQueryP(q, params)
      .then((rows) => {
        if (!rows || !rows.length) {
          fail(res, 500, 'polis_err_closing_conversation_no_such_conversation');
          return;
        }
        const conv = rows[0];
        pgQueryP('update conversations set is_active = true where zid = ($1);', [conv.zid])
          .then(() => {
            res.status(200).json({});
          })
          .catch((err) => {
            fail(res, 500, 'polis_err_reopening_conversation2', err);
          });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_reopening_conversation', err);
      });
  }
  function handle_PUT_users(req, res) {
    let uid = req.p.uid;
    if (isPolisDev(uid) && req.p.uid_of_user) {
      uid = req.p.uid_of_user;
    }
    const fields = {};
    if (!_.isUndefined(req.p.email)) {
      fields.email = req.p.email;
    }
    if (!_.isUndefined(req.p.hname)) {
      fields.hname = req.p.hname;
    }
    const q = sql_users.update(fields).where(sql_users.uid.equals(uid));
    pgQueryP(q.toString(), [])
      .then((result) => {
        res.json(result);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_put_user', err);
      });
  }
  function handle_PUT_conversations(req, res) {
    const generateShortUrl = req.p.short_url;
    isModerator(req.p.zid, req.p.uid)
      .then((ok) => {
        if (!ok) {
          fail(res, 403, 'polis_err_update_conversation_permission');
          return;
        }
        let verifyMetaPromise;
        if (req.p.verifyMeta) {
          verifyMetaPromise = verifyMetadataAnswersExistForEachQuestion(req.p.zid);
        } else {
          verifyMetaPromise = Promise.resolve();
        }
        const fields = {};
        if (!_.isUndefined(req.p.is_active)) {
          fields.is_active = req.p.is_active;
        }
        if (!_.isUndefined(req.p.is_anon)) {
          fields.is_anon = req.p.is_anon;
        }
        if (!_.isUndefined(req.p.is_draft)) {
          fields.is_draft = req.p.is_draft;
        }
        if (!_.isUndefined(req.p.is_data_open)) {
          fields.is_data_open = req.p.is_data_open;
        }
        if (!_.isUndefined(req.p.profanity_filter)) {
          fields.profanity_filter = req.p.profanity_filter;
        }
        if (!_.isUndefined(req.p.spam_filter)) {
          fields.spam_filter = req.p.spam_filter;
        }
        if (!_.isUndefined(req.p.strict_moderation)) {
          fields.strict_moderation = req.p.strict_moderation;
        }
        if (!_.isUndefined(req.p.topic)) {
          fields.topic = req.p.topic;
        }
        if (!_.isUndefined(req.p.description)) {
          fields.description = req.p.description;
        }
        if (!_.isUndefined(req.p.vis_type)) {
          fields.vis_type = req.p.vis_type;
        }
        if (!_.isUndefined(req.p.help_type)) {
          fields.help_type = req.p.help_type;
        }
        if (!_.isUndefined(req.p.socialbtn_type)) {
          fields.socialbtn_type = req.p.socialbtn_type;
        }
        if (!_.isUndefined(req.p.bgcolor)) {
          if (req.p.bgcolor === 'default') {
            fields.bgcolor = null;
          } else {
            fields.bgcolor = req.p.bgcolor;
          }
        }
        if (!_.isUndefined(req.p.help_color)) {
          if (req.p.help_color === 'default') {
            fields.help_color = null;
          } else {
            fields.help_color = req.p.help_color;
          }
        }
        if (!_.isUndefined(req.p.help_bgcolor)) {
          if (req.p.help_bgcolor === 'default') {
            fields.help_bgcolor = null;
          } else {
            fields.help_bgcolor = req.p.help_bgcolor;
          }
        }
        if (!_.isUndefined(req.p.style_btn)) {
          fields.style_btn = req.p.style_btn;
        }
        if (!_.isUndefined(req.p.write_type)) {
          fields.write_type = req.p.write_type;
        }
        ifDefinedSet('auth_opt_allow_3rdparty', req.p, fields);
        if (!_.isUndefined(req.p.owner_sees_participation_stats)) {
          fields.owner_sees_participation_stats = !!req.p.owner_sees_participation_stats;
        }
        if (!_.isUndefined(req.p.link_url)) {
          fields.link_url = req.p.link_url;
        }
        ifDefinedSet('subscribe_type', req.p, fields);
        const q = sql_conversations.update(fields).where(sql_conversations.zid.equals(req.p.zid)).returning('*');
        verifyMetaPromise.then(
          () => {
            pgQuery(q.toString(), (err, result) => {
              if (err) {
                fail(res, 500, 'polis_err_update_conversation', err);
                return;
              }
              const conv = result?.rows?.[0];
              conv.is_mod = true;
              const promise = generateShortUrl
                ? generateAndReplaceZinvite(req.p.zid, generateShortUrl)
                : Promise.resolve();
              const successCode = generateShortUrl ? 201 : 200;
              promise
                .then(() => {
                  if (req.p.send_created_email) {
                    Promise.all([getUserInfoForUid2(req.p.uid), getConversationUrl(req, req.p.zid, true)])
                      .then((results) => {
                        const hname = results[0].hname;
                        const url = results[1];
                        sendEmailByUid(
                          req.p.uid,
                          'Conversation created',
                          `Hi ${hname},\n\nHere's a link to the conversation you just created. Use it to invite participants to the conversation. Share it by whatever network you prefer - Gmail, Facebook, Twitter, etc., or just post it to your website or blog. Try it now! Click this link to go to your conversation:\n${url}\n\nWith gratitude,\n\nThe team at pol.is\n`
                        ).catch((err) => {
                          logger.error('polis_err_sending_conversation_created_email', err);
                        });
                      })
                      .catch((err) => {
                        logger.error('polis_err_sending_conversation_created_email', err);
                      });
                  }
                  finishOne(res, conv, true, successCode);
                  updateConversationModifiedTime(req.p.zid);
                })
                .catch((err) => {
                  fail(res, 500, 'polis_err_update_conversation', err);
                });
            });
          },
          (err) => {
            fail(res, 500, err.message, err);
          }
        );
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_update_conversation', err);
      });
  }
  function handle_DELETE_metadata_questions(req, res) {
    const uid = req.p.uid;
    const pmqid = req.p.pmqid;
    getZidForQuestion(pmqid, (err, zid) => {
      if (err) {
        fail(res, 500, 'polis_err_delete_participant_metadata_questions_zid', err);
        return;
      }
      isConversationOwner(zid, uid, (err) => {
        if (err) {
          fail(res, 403, 'polis_err_delete_participant_metadata_questions_auth', err);
          return;
        }
        deleteMetadataQuestionAndAnswers(pmqid, (err) => {
          if (err) {
            fail(res, 500, 'polis_err_delete_participant_metadata_question', new Error(err));
            return;
          }
          res.send(200);
        });
      });
    });
  }
  function handle_DELETE_metadata_answers(req, res) {
    const uid = req.p.uid;
    const pmaid = req.p.pmaid;
    getZidForAnswer(pmaid, (err, zid) => {
      if (err) {
        fail(res, 500, 'polis_err_delete_participant_metadata_answers_zid', err);
        return;
      }
      isConversationOwner(zid, uid, (err) => {
        if (err) {
          fail(res, 403, 'polis_err_delete_participant_metadata_answers_auth', err);
          return;
        }
        deleteMetadataAnswer(pmaid, (err) => {
          if (err) {
            fail(res, 500, 'polis_err_delete_participant_metadata_answers', err);
            return;
          }
          res.send(200);
        });
      });
    });
  }
  function getZidForAnswer(pmaid, callback) {
    pgQuery('SELECT zid FROM participant_metadata_answers WHERE pmaid = ($1);', [pmaid], (err, result) => {
      if (err) {
        callback(err);
        return;
      }
      if (!result.rows || !result.rows.length) {
        callback('polis_err_zid_missing_for_answer');
        return;
      }
      callback(null, result.rows[0].zid);
    });
  }
  function getZidForQuestion(pmqid, callback) {
    pgQuery('SELECT zid FROM participant_metadata_questions WHERE pmqid = ($1);', [pmqid], (err, result) => {
      if (err) {
        logger.error('polis_err_zid_missing_for_question', err);
        callback(err);
        return;
      }
      if (!result.rows || !result.rows.length) {
        callback('polis_err_zid_missing_for_question');
        return;
      }
      callback(null, result.rows[0].zid);
    });
  }
  function deleteMetadataAnswer(pmaid, callback) {
    pgQuery('update participant_metadata_answers set alive = FALSE where pmaid = ($1);', [pmaid], (err) => {
      if (err) {
        callback(err);
        return;
      }
      callback(null);
    });
  }
  function deleteMetadataQuestionAndAnswers(pmqid, callback) {
    pgQuery('update participant_metadata_answers set alive = FALSE where pmqid = ($1);', [pmqid], (err) => {
      if (err) {
        callback(err);
        return;
      }
      pgQuery('update participant_metadata_questions set alive = FALSE where pmqid = ($1);', [pmqid], (err) => {
        if (err) {
          callback(err);
          return;
        }
        callback(null);
      });
    });
  }
  function handle_GET_metadata_questions(req, res) {
    const zid = req.p.zid;
    const zinvite = req.p.zinvite;
    const suzinvite = req.p.suzinvite;
    function doneChecking(err, _foo) {
      if (err) {
        fail(res, 403, 'polis_err_get_participant_metadata_auth', err);
        return;
      }
      async.parallel(
        [
          (callback) => {
            pgQuery_readOnly(
              'SELECT * FROM participant_metadata_questions WHERE alive = true AND zid = ($1);',
              [zid],
              callback
            );
          }
        ],
        (err, result) => {
          if (err) {
            fail(res, 500, 'polis_err_get_participant_metadata_questions', err);
            return;
          }
          let rows = result[0]?.rows;
          rows = rows.map((r) => {
            r.required = true;
            return r;
          });
          finishArray(res, rows);
        }
      );
    }
    if (zinvite) {
      checkZinviteCodeValidity(zid, zinvite, doneChecking);
    } else if (suzinvite) {
      checkSuzinviteCodeValidity(zid, suzinvite, doneChecking);
    } else {
      doneChecking(false);
    }
  }
  function handle_POST_metadata_questions(req, res) {
    const zid = req.p.zid;
    const key = req.p.key;
    const uid = req.p.uid;
    function doneChecking(err, _foo) {
      if (err) {
        fail(res, 403, 'polis_err_post_participant_metadata_auth', err);
        return;
      }
      pgQuery(
        'INSERT INTO participant_metadata_questions (pmqid, zid, key) VALUES (default, $1, $2) RETURNING *;',
        [zid, key],
        (err, results) => {
          if (err || !results || !results.rows || !results.rows.length) {
            fail(res, 500, 'polis_err_post_participant_metadata_key', err);
            return;
          }
          finishOne(res, results.rows[0]);
        }
      );
    }
    isConversationOwner(zid, uid, doneChecking);
  }
  function handle_POST_metadata_answers(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const pmqid = req.p.pmqid;
    const value = req.p.value;
    function doneChecking(err, _foo) {
      if (err) {
        fail(res, 403, 'polis_err_post_participant_metadata_auth', err);
        return;
      }
      pgQuery(
        'INSERT INTO participant_metadata_answers (pmqid, zid, value, pmaid) VALUES ($1, $2, $3, default) RETURNING *;',
        [pmqid, zid, value],
        (err, results) => {
          if (err || !results || !results.rows || !results.rows.length) {
            pgQuery(
              'UPDATE participant_metadata_answers set alive = TRUE where pmqid = ($1) AND zid = ($2) AND value = ($3) RETURNING *;',
              [pmqid, zid, value],
              (err, results) => {
                if (err) {
                  fail(res, 500, 'polis_err_post_participant_metadata_value', err);
                  return;
                }
                finishOne(res, results.rows[0]);
              }
            );
          } else {
            finishOne(res, results.rows[0]);
          }
        }
      );
    }
    isConversationOwner(zid, uid, doneChecking);
  }
  function handle_GET_metadata_choices(req, res) {
    const zid = req.p.zid;
    getChoicesForConversation(zid).then(
      (choices) => {
        finishArray(res, choices);
      },
      (err) => {
        fail(res, 500, 'polis_err_get_participant_metadata_choices', err);
      }
    );
  }
  function handle_GET_metadata_answers(req, res) {
    const zid = req.p.zid;
    const zinvite = req.p.zinvite;
    const suzinvite = req.p.suzinvite;
    const pmqid = req.p.pmqid;
    function doneChecking(err, _foo) {
      if (err) {
        fail(res, 403, 'polis_err_get_participant_metadata_auth', err);
        return;
      }
      let query = sql_participant_metadata_answers
        .select(sql_participant_metadata_answers.star())
        .where(sql_participant_metadata_answers.zid.equals(zid))
        .and(sql_participant_metadata_answers.alive.equals(true));
      if (pmqid) {
        query = query.where(sql_participant_metadata_answers.pmqid.equals(pmqid));
      }
      pgQuery_readOnly(query.toString(), (err, result) => {
        if (err) {
          fail(res, 500, 'polis_err_get_participant_metadata_answers', err);
          return;
        }
        const rows = result.rows.map((r) => {
          r.is_exclusive = true;
          return r;
        });
        finishArray(res, rows);
      });
    }
    if (zinvite) {
      checkZinviteCodeValidity(zid, zinvite, doneChecking);
    } else if (suzinvite) {
      checkSuzinviteCodeValidity(zid, suzinvite, doneChecking);
    } else {
      doneChecking(false);
    }
  }
  function handle_GET_metadata(req, res) {
    const zid = req.p.zid;
    const zinvite = req.p.zinvite;
    const suzinvite = req.p.suzinvite;
    function doneChecking(err) {
      if (err) {
        fail(res, 403, 'polis_err_get_participant_metadata_auth', err);
        return;
      }
      async.parallel(
        [
          (callback) => {
            pgQuery_readOnly('SELECT * FROM participant_metadata_questions WHERE zid = ($1);', [zid], callback);
          },
          (callback) => {
            pgQuery_readOnly('SELECT * FROM participant_metadata_answers WHERE zid = ($1);', [zid], callback);
          },
          (callback) => {
            pgQuery_readOnly('SELECT * FROM participant_metadata_choices WHERE zid = ($1);', [zid], callback);
          }
        ],
        (err, result) => {
          if (err) {
            fail(res, 500, 'polis_err_get_participant_metadata', err);
            return;
          }
          const keys = result[0]?.rows;
          const vals = result[1]?.rows;
          const choices = result[2]?.rows;
          const o = {};
          const keyNames = {};
          const valueNames = {};
          let i;
          let k;
          let v;
          if (!keys || !keys.length) {
            res.status(200).json({});
            return;
          }
          for (i = 0; i < keys.length; i++) {
            k = keys[i];
            o[k.pmqid] = {};
            keyNames[k.pmqid] = k.key;
          }
          for (i = 0; i < vals.length; i++) {
            k = vals[i];
            v = vals[i];
            o[k.pmqid][v.pmaid] = [];
            valueNames[v.pmaid] = v.value;
          }
          for (i = 0; i < choices.length; i++) {
            o[choices[i].pmqid][choices[i].pmaid] = choices[i].pid;
          }
          res.status(200).json({
            kvp: o,
            keys: keyNames,
            values: valueNames
          });
        }
      );
    }
    if (zinvite) {
      checkZinviteCodeValidity(zid, zinvite, doneChecking);
    } else if (suzinvite) {
      checkSuzinviteCodeValidity(zid, suzinvite, doneChecking);
    } else {
      doneChecking(false);
    }
  }
  function getConversationHasMetadata(zid) {
    return new Promise((resolve, reject) => {
      pgQuery_readOnly(
        'SELECT * from participant_metadata_questions where zid = ($1)',
        [zid],
        (err, metadataResults) => {
          if (err) {
            return reject('polis_err_get_conversation_metadata_by_zid');
          }
          const hasNoMetadata = !metadataResults || !metadataResults.rows || !metadataResults.rows.length;
          resolve(!hasNoMetadata);
        }
      );
    });
  }
  function getConversationTranslations(zid, lang) {
    const firstTwoCharsOfLang = lang.substr(0, 2);
    return pgQueryP('select * from conversation_translations where zid = ($1) and lang = ($2);', [
      zid,
      firstTwoCharsOfLang
    ]);
  }
  function getConversationTranslationsMinimal(zid, lang) {
    if (!lang) {
      return Promise.resolve([]);
    }
    return getConversationTranslations(zid, lang).then((rows) => {
      for (let i = 0; i < rows.length; i++) {
        rows[i].zid = undefined;
        rows[i].created = undefined;
        rows[i].modified = undefined;
        rows[i].src = undefined;
      }
      return rows;
    });
  }
  function getOneConversation(zid, uid, lang) {
    return Promise.all([
      pgQueryP_readOnly(
        'select * from conversations left join  (select uid, site_id from users) as u on conversations.owner = u.uid where conversations.zid = ($1);',
        [zid]
      ),
      getConversationHasMetadata(zid),
      _.isUndefined(uid) ? Promise.resolve({}) : getUserInfoForUid2(uid),
      getConversationTranslationsMinimal(zid, lang)
    ]).then((results) => {
      const conv = results[0]?.[0];
      const convHasMetadata = results[1];
      const requestingUserInfo = results[2];
      const translations = results[3];
      conv.auth_opt_allow_3rdparty = ifDefinedFirstElseSecond(conv.auth_opt_allow_3rdparty, true);
      conv.auth_opt_fb_computed = false;
      conv.auth_opt_tw_computed = false;
      conv.translations = translations;
      return getUserInfoForUid2(conv.owner).then((ownerInfo) => {
        const ownername = ownerInfo.hname;
        if (convHasMetadata) {
          conv.hasMetadata = true;
        }
        if (!_.isUndefined(ownername) && conv.context !== 'hongkong2014') {
          conv.ownername = ownername;
        }
        conv.is_mod = conv.site_id === requestingUserInfo.site_id;
        conv.is_owner = conv.owner === uid;
        conv.uid = undefined;
        return conv;
      });
    });
  }
  function getConversations(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    const xid = req.p.xid;
    const include_all_conversations_i_am_in = req.p.include_all_conversations_i_am_in;
    const want_mod_url = req.p.want_mod_url;
    const want_upvoted = req.p.want_upvoted;
    const want_inbox_item_admin_url = req.p.want_inbox_item_admin_url;
    const want_inbox_item_participant_url = req.p.want_inbox_item_participant_url;
    const want_inbox_item_admin_html = req.p.want_inbox_item_admin_html;
    const want_inbox_item_participant_html = req.p.want_inbox_item_participant_html;
    const _context = req.p.context;
    let zidListQuery =
      'select zid, 1 as type from conversations where owner in (select uid from users where site_id = (select site_id from users where uid = ($1)))';
    if (include_all_conversations_i_am_in) {
      zidListQuery += ' UNION ALL select zid, 2 as type from participants where uid = ($1)';
    }
    zidListQuery += ';';
    pgQuery_readOnly(zidListQuery, [uid], (err, results) => {
      if (err) {
        fail(res, 500, 'polis_err_get_conversations_participated_in', err);
        return;
      }
      const participantInOrSiteAdminOf = (results?.rows && _.pluck(results.rows, 'zid')) || null;
      const siteAdminOf = _.filter(results.rows, (row) => row.type === 1);
      const isSiteAdmin = _.indexBy(siteAdminOf, 'zid');
      let query = sql_conversations.select(sql_conversations.star());
      let isRootsQuery = false;
      let orClauses;
      if (!_.isUndefined(req.p.context)) {
        if (req.p.context === '/') {
          orClauses = sql_conversations.is_public.equals(true);
          isRootsQuery = true;
        } else {
          orClauses = sql_conversations.context.equals(req.p.context);
        }
      } else {
        orClauses = sql_conversations.owner.equals(uid);
        if (participantInOrSiteAdminOf.length) {
          orClauses = orClauses.or(sql_conversations.zid.in(participantInOrSiteAdminOf));
        }
      }
      query = query.where(orClauses);
      if (!_.isUndefined(req.p.course_invite)) {
        query = query.and(sql_conversations.course_id.equals(req.p.course_id));
      }
      if (!_.isUndefined(req.p.is_active)) {
        query = query.and(sql_conversations.is_active.equals(req.p.is_active));
      }
      if (!_.isUndefined(req.p.is_draft)) {
        query = query.and(sql_conversations.is_draft.equals(req.p.is_draft));
      }
      if (!_.isUndefined(req.p.zid)) {
        query = query.and(sql_conversations.zid.equals(zid));
      }
      if (isRootsQuery) {
        query = query.and(sql_conversations.context.isNotNull());
      }
      query = query.order(sql_conversations.created.descending);
      if (!_.isUndefined(req.p.limit)) {
        query = query.limit(req.p.limit);
      } else {
        query = query.limit(999);
      }
      pgQuery_readOnly(query.toString(), (err, result) => {
        if (err) {
          fail(res, 500, 'polis_err_get_conversations', err);
          return;
        }
        const data = result.rows || [];
        addConversationIds(data)
          .then((data) => {
            let suurlsPromise;
            if (xid) {
              suurlsPromise = Promise.all(
                data.map((conv) => createOneSuzinvite(xid, conv.zid, conv.owner, _.partial(generateSingleUseUrl, req)))
              );
            } else {
              suurlsPromise = Promise.resolve();
            }
            const upvotesPromise =
              uid && want_upvoted
                ? pgQueryP_readOnly('select zid from upvotes where uid = ($1);', [uid])
                : Promise.resolve();
            return Promise.all([suurlsPromise, upvotesPromise]).then(
              (x) => {
                let suurlData = x[0];
                let upvotes = x[1];
                if (suurlData) {
                  suurlData = _.indexBy(suurlData, 'zid');
                }
                if (upvotes) {
                  upvotes = _.indexBy(upvotes, 'zid');
                }
                data.forEach((conv) => {
                  conv.is_owner = conv.owner === uid;
                  const root = getServerNameWithProtocol(req);
                  if (want_mod_url) {
                    conv.mod_url = createModerationUrl(req, conv.conversation_id);
                  }
                  if (want_inbox_item_admin_url) {
                    conv.inbox_item_admin_url = `${root}/iim/${conv.conversation_id}`;
                  }
                  if (want_inbox_item_participant_url) {
                    conv.inbox_item_participant_url = `${root}/iip/${conv.conversation_id}`;
                  }
                  if (want_inbox_item_admin_html) {
                    conv.inbox_item_admin_html = `<a href='${root}/${conv.conversation_id}'>${conv.topic || conv.created}</a> <a href='${root}/m/${conv.conversation_id}'>moderate</a>`;
                    conv.inbox_item_admin_html_escaped = conv.inbox_item_admin_html.replace(/'/g, "\\'");
                  }
                  if (want_inbox_item_participant_html) {
                    conv.inbox_item_participant_html = `<a href='${root}/${conv.conversation_id}'>${conv.topic || conv.created}</a>`;
                    conv.inbox_item_participant_html_escaped = conv.inbox_item_admin_html.replace(/'/g, "\\'");
                  }
                  if (suurlData) {
                    conv.url = suurlData[conv.zid || ''].suurl;
                  } else {
                    conv.url = buildConversationUrl(req, conv.conversation_id);
                  }
                  if (upvotes?.[conv.zid || '']) {
                    conv.upvoted = true;
                  }
                  conv.created = Number(conv.created);
                  conv.modified = Number(conv.modified);
                  if (_.isUndefined(conv.topic) || conv.topic === '') {
                    conv.topic = new Date(conv.created).toUTCString();
                  }
                  conv.is_mod = conv.is_owner || isSiteAdmin[conv.zid || ''];
                  conv.zid = undefined;
                  conv.is_anon = undefined;
                  conv.is_draft = undefined;
                  conv.is_public = undefined;
                  if (conv.context === '') {
                    conv.context = undefined;
                  }
                });
                res.status(200).json(data);
              },
              (err) => {
                fail(res, 500, 'polis_err_get_conversations_surls', err);
              }
            );
          })
          .catch((err) => {
            fail(res, 500, 'polis_err_get_conversations_misc', err);
          });
      });
    });
  }
  function createReport(zid) {
    return generateTokenP(20, false).then((report_id) => {
      report_id = `r${report_id}`;
      return pgQueryP('insert into reports (zid, report_id) values ($1, $2);', [zid, report_id]);
    });
  }
  function handle_POST_reports(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    return isModerator(zid, uid)
      .then((isMod, err) => {
        if (!isMod) {
          return fail(res, 403, 'polis_err_post_reports_permissions', err);
        }
        return createReport(zid).then(() => {
          res.json({});
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_post_reports_misc', err);
      });
  }
  function handle_PUT_reports(req, res) {
    const rid = req.p.rid;
    const uid = req.p.uid;
    const zid = req.p.zid;
    return isModerator(zid, uid)
      .then((isMod, err) => {
        if (!isMod) {
          return fail(res, 403, 'polis_err_put_reports_permissions', err);
        }
        const fields = {
          modified: 'now_as_millis()'
        };
        sql_reports.columns
          .map((c) => {
            return c.name;
          })
          .filter((name) => {
            return name.startsWith('label_');
          })
          .forEach((name) => {
            if (!_.isUndefined(req.p[name])) {
              fields[name] = req.p[name];
            }
          });
        if (!_.isUndefined(req.p.report_name)) {
          fields.report_name = req.p.report_name;
        }
        const q = sql_reports.update(fields).where(sql_reports.rid.equals(rid));
        let query = q.toString();
        query = query.replace("'now_as_millis()'", 'now_as_millis()');
        return pgQueryP(query, []).then((_result) => {
          res.json({});
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_post_reports_misc', err);
      });
  }
  function handle_GET_reports(req, res) {
    const zid = req.p.zid;
    const rid = req.p.rid;
    const uid = req.p.uid;
    let reportsPromise = null;
    if (rid) {
      if (zid) {
        reportsPromise = Promise.reject('polis_err_get_reports_should_not_specify_both_report_id_and_conversation_id');
      } else {
        reportsPromise = pgQueryP('select * from reports where rid = ($1);', [rid]);
      }
    } else if (zid) {
      reportsPromise = isModerator(zid, uid).then((doesOwnConversation) => {
        if (!doesOwnConversation) {
          throw 'polis_err_permissions';
        }
        return pgQueryP('select * from reports where zid = ($1);', [zid]);
      });
    } else {
      reportsPromise = pgQueryP(
        'select * from reports where zid in (select zid from conversations where owner = ($1));',
        [uid]
      );
    }
    reportsPromise
      .then((reports) => {
        const zids = [];
        reports = reports.map((report) => {
          zids.push(report.zid);
          report.rid = undefined;
          return report;
        });
        if (zids.length === 0) {
          return res.json(reports);
        }
        return pgQueryP(`select * from zinvites where zid in (${zids.join(',')});`, []).then((zinvite_entries) => {
          const zidToZinvite = _.indexBy(zinvite_entries, 'zid');
          reports = reports.map((report) => {
            report.conversation_id = zidToZinvite[report.zid || '']?.zinvite;
            report.zid = undefined;
            return report;
          });
          res.json(reports);
        });
      })
      .catch((err) => {
        if (err === 'polis_err_permissions') {
          fail(res, 403, 'polis_err_permissions');
        } else if (err === 'polis_err_get_reports_should_not_specify_both_report_id_and_conversation_id') {
          fail(res, 404, 'polis_err_get_reports_should_not_specify_both_report_id_and_conversation_id');
        } else {
          fail(res, 500, 'polis_err_get_reports_misc', err);
        }
      });
  }
  function encodeParams(o) {
    const stringifiedJson = JSON.stringify(o);
    const encoded = `ep1_${strToHex(stringifiedJson)}`;
    return encoded;
  }
  function handle_GET_conversations(req, res) {
    let courseIdPromise = Promise.resolve();
    if (req.p.course_invite) {
      courseIdPromise = pgQueryP_readOnly('select course_id from courses where course_invite = ($1);', [
        req.p.course_invite
      ]).then((rows) => rows[0].course_id);
    }
    courseIdPromise.then((course_id) => {
      if (course_id) {
        req.p.course_id = course_id;
      }
      const lang = null;
      if (req.p.zid) {
        getOneConversation(req.p.zid, req.p.uid, lang)
          .then(
            (data) => {
              finishOne(res, data);
            },
            (err) => {
              fail(res, 500, 'polis_err_get_conversations_2', err);
            }
          )
          .catch((err) => {
            fail(res, 500, 'polis_err_get_conversations_1', err);
          });
      } else if (req.p.uid || req.p.context) {
        getConversations(req, res);
      } else {
        fail(res, 403, 'polis_err_need_auth');
      }
    });
  }
  function handle_GET_contexts(_req, res) {
    pgQueryP_readOnly('select name from contexts where is_public = TRUE order by name;', [])
      .then(
        (contexts) => {
          res.status(200).json(contexts);
        },
        (err) => {
          fail(res, 500, 'polis_err_get_contexts_query', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_get_contexts_misc', err);
      });
  }
  function handle_POST_contexts(req, res) {
    const uid = req.p.uid;
    const name = req.p.name;
    function createContext() {
      return pgQueryP('insert into contexts (name, creator, is_public) values ($1, $2, $3);', [name, uid, true])
        .then(
          () => {
            res.status(200).json({});
          },
          (err) => {
            fail(res, 500, 'polis_err_post_contexts_query', err);
          }
        )
        .catch((err) => {
          fail(res, 500, 'polis_err_post_contexts_misc', err);
        });
    }
    pgQueryP('select name from contexts where name = ($1);', [name])
      .then(
        (rows) => {
          const exists = rows?.length;
          if (exists) {
            fail(res, 422, 'polis_err_post_context_exists');
            return;
          }
          return createContext();
        },
        (err) => {
          fail(res, 500, 'polis_err_post_contexts_check_query', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_post_contexts_check_misc', err);
      });
  }
  function isUserAllowedToCreateConversations(_uid, callback) {
    callback?.(null, true);
  }
  function handle_POST_reserve_conversation_id(_req, res) {
    const zid = 0;
    const shortUrl = false;
    generateAndRegisterZinvite(zid, shortUrl)
      .then((conversation_id) => {
        res.json({
          conversation_id: conversation_id
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_reserve_conversation_id', err);
      });
  }
  function handle_POST_conversations(req, res) {
    const xidStuffReady = Promise.resolve();
    xidStuffReady
      .then(() => {
        const generateShortUrl = req.p.short_url;
        isUserAllowedToCreateConversations(req.p.uid, (err, isAllowed) => {
          if (err) {
            fail(res, 403, 'polis_err_add_conversation_failed_user_check', err);
            return;
          }
          if (!isAllowed) {
            fail(
              res,
              403,
              'polis_err_add_conversation_not_enabled',
              new Error('polis_err_add_conversation_not_enabled')
            );
            return;
          }
          const q = sql_conversations
            .insert({
              owner: req.p.uid,
              org_id: req.p.org_id || req.p.uid,
              topic: req.p.topic,
              description: req.p.description,
              is_active: req.p.is_active,
              is_data_open: req.p.is_data_open,
              is_draft: req.p.is_draft,
              is_public: true,
              is_anon: req.p.is_anon,
              profanity_filter: req.p.profanity_filter,
              spam_filter: req.p.spam_filter,
              strict_moderation: req.p.strict_moderation,
              context: req.p.context || null,
              owner_sees_participation_stats: !!req.p.owner_sees_participation_stats,
              auth_needed_to_vote: DEFAULTS.auth_needed_to_vote,
              auth_needed_to_write: DEFAULTS.auth_needed_to_write,
              auth_opt_allow_3rdparty: req.p.auth_opt_allow_3rdparty || DEFAULTS.auth_opt_allow_3rdparty,
              auth_opt_fb: DEFAULTS.auth_opt_fb,
              auth_opt_tw: DEFAULTS.auth_opt_tw
            })
            .returning('*')
            .toString();
          pgQuery(q, [], (err, result) => {
            if (err) {
              if (isDuplicateKey(err)) {
                logger.error('polis_err_add_conversation', err);
                failWithRetryRequest(res);
              } else {
                fail(res, 500, 'polis_err_add_conversation', err);
              }
              return;
            }
            const zid = result?.rows?.[0]?.zid;
            const zinvitePromise = req.p.conversation_id
              ? Conversation.getZidFromConversationId(req.p.conversation_id).then((zid) => {
                  return zid === 0 ? req.p.conversation_id : null;
                })
              : generateAndRegisterZinvite(zid, generateShortUrl);
            zinvitePromise
              .then((zinvite) => {
                if (zinvite === null) {
                  fail(res, 400, 'polis_err_conversation_id_already_in_use', err);
                  return;
                }
                finishOne(res, {
                  url: buildConversationUrl(req, zinvite),
                  zid: zid
                });
              })
              .catch((err) => {
                fail(res, 500, 'polis_err_zinvite_create', err);
              });
          });
        });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_conversation_create', err);
      });
  }
  function handle_POST_query_participants_by_metadata(req, res) {
    const uid = req.p.uid;
    const zid = req.p.zid;
    const pmaids = req.p.pmaids;
    if (!pmaids.length) {
      return res.status(200).json([]);
    }
    function doneChecking() {
      pgQuery_readOnly(
        `select pid from participants where zid = ($1) and pid not in (select pid from participant_metadata_choices where alive = TRUE and pmaid in (select pmaid from participant_metadata_answers where alive = TRUE and zid = ($2) and pmaid not in (${pmaids.join(',')})));`,
        [zid, zid],
        (err, results) => {
          if (err) {
            fail(res, 500, 'polis_err_metadata_query', err);
            return;
          }
          res.status(200).json(_.pluck(results.rows, 'pid'));
        }
      );
    }
    isOwnerOrParticipant(zid, uid, doneChecking);
  }
  function handle_POST_sendCreatedLinkToEmail(req, res) {
    pgQuery_readOnly('SELECT * FROM users WHERE uid = $1', [req.p.uid], (err, results) => {
      if (err) {
        fail(res, 500, 'polis_err_get_email_db', err);
        return;
      }
      const email = results.rows[0].email;
      const fullname = results.rows[0].hname;
      pgQuery_readOnly('select * from zinvites where zid = $1', [req.p.zid], (_err, results) => {
        const zinvite = results.rows[0].zinvite;
        const server = getServerNameWithProtocol(req);
        const createdLink = `${server}/#${req.p.zid}/${zinvite}`;
        const body = `Hi ${fullname},\n\nHere's a link to the conversation you just created. Use it to invite participants to the conversation. Share it by whatever network you prefer - Gmail, Facebook, Twitter, etc., or just post it to your website or blog. Try it now! Click this link to go to your conversation: \n\n${createdLink}\n\nWith gratitude,\n\nThe team at pol.is`;
        return sendTextEmail(polisFromAddress, email, `Link: ${createdLink}`, body)
          .then(() => {
            res.status(200).json({});
          })
          .catch((err) => {
            fail(res, 500, 'polis_err_sending_created_link_to_email', err);
          });
      });
    });
  }
  function handle_POST_notifyTeam(req, res) {
    if (req.p.webserver_pass !== Config.webserverPass || req.p.webserver_username !== Config.webserverUsername) {
      return fail(res, 403, 'polis_err_notifyTeam_auth');
    }
    const subject = req.p.subject;
    const body = req.p.body;
    emailTeam(subject, body)
      .then(() => {
        res.status(200).json({});
      })
      .catch((err) => {
        return fail(res, 500, 'polis_err_notifyTeam', err);
      });
  }
  function handle_POST_sendEmailExportReady(req, res) {
    if (req.p.webserver_pass !== Config.webserverPass || req.p.webserver_username !== Config.webserverUsername) {
      return fail(res, 403, 'polis_err_sending_export_link_to_email_auth');
    }
    const serverUrl = Config.getServerUrl();
    const email = req.p.email;
    const subject = `Polis data export for conversation pol.is/${req.p.conversation_id}`;
    const fromAddress = `Polis Team <${Config.adminEmailDataExport}>`;
    const body = `Greetings

You created a data export for conversation ${serverUrl}/${req.p.conversation_id} that has just completed. You can download the results for this conversation at the following url:

${serverUrl}/api/v3/dataExport/results?filename=${req.p.filename}&conversation_id=${req.p.conversation_id}

Please let us know if you have any questions about the data.

Thanks for using Polis!
`;
    sendTextEmail(fromAddress, email, subject, body)
      .then(() => {
        res.status(200).json({});
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_sending_export_link_to_email', err);
      });
  }
  function getTwitterRequestToken(returnUrl) {
    const oauth = new OAuth.OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      Config.twitterConsumerKey,
      Config.twitterConsumerSecret,
      '1.0A',
      null,
      'HMAC-SHA1'
    );
    const body = {
      oauth_callback: returnUrl
    };
    return new Promise((resolve, reject) => {
      oauth.post(
        'https://api.twitter.com/oauth/request_token',
        void 0,
        void 0,
        body,
        'multipart/form-data',
        (err, data, _res) => {
          if (err) {
            logger.error('get twitter token failed', err);
            reject(err);
          } else {
            resolve(data);
          }
        }
      );
    });
  }
  function handle_GET_twitterBtn(req, res) {
    let dest = req.p.dest || '/inbox';
    dest = encodeURIComponent(getServerNameWithProtocol(req) + dest);
    const returnUrl = `${getServerNameWithProtocol(req)}/api/v3/twitter_oauth_callback?owner=${req.p.owner}&dest=${dest}`;
    getTwitterRequestToken(returnUrl)
      .then((data) => {
        data += `&callback_url=${dest}`;
        res.redirect(`https://api.twitter.com/oauth/authenticate?${data}`);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_twitter_auth_01', err);
      });
  }
  function getTwitterAccessToken(body) {
    const oauth = new OAuth.OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      Config.twitterConsumerKey,
      Config.twitterConsumerSecret,
      '1.0A',
      null,
      'HMAC-SHA1'
    );
    return new Promise((resolve, reject) => {
      oauth.post(
        'https://api.twitter.com/oauth/access_token',
        void 0,
        void 0,
        body,
        'multipart/form-data',
        (err, data, _res) => {
          if (err) {
            logger.error('get twitter token failed', err);
            reject(err);
          } else {
            resolve(data);
          }
        }
      );
    });
  }
  const twitterUserInfoCache = new LruCache({
    max: 10000
  });
  function getTwitterUserInfo(o, useCache) {
    const twitter_user_id = o.twitter_user_id;
    const twitter_screen_name = o.twitter_screen_name;
    const params = {};
    let identifier;
    if (twitter_user_id) {
      params.user_id = twitter_user_id;
      identifier = twitter_user_id;
    } else if (twitter_screen_name) {
      params.screen_name = twitter_screen_name;
      identifier = twitter_screen_name;
    }
    const oauth = new OAuth.OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      Config.twitterConsumerKey,
      Config.twitterConsumerSecret,
      '1.0A',
      null,
      'HMAC-SHA1'
    );
    return new MPromise('getTwitterUserInfo', (resolve, reject) => {
      const cachedCopy = twitterUserInfoCache.get(identifier);
      if (useCache && cachedCopy) {
        return resolve(cachedCopy);
      }
      if (suspendedOrPotentiallyProblematicTwitterIds.indexOf(identifier) >= 0) {
        return reject();
      }
      oauth.post(
        'https://api.twitter.com/1.1/users/lookup.json',
        void 0,
        void 0,
        params,
        'multipart/form-data',
        (err, data, _res) => {
          if (err) {
            logger.error(`get twitter token failed for identifier: ${identifier}`, err);
            suspendedOrPotentiallyProblematicTwitterIds.push(identifier);
            reject(err);
          } else {
            twitterUserInfoCache.set(identifier, data);
            resolve(data);
          }
        }
      );
    });
  }
  function getTwitterTweetById(twitter_tweet_id) {
    const oauth = new OAuth.OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      Config.twitterConsumerKey,
      Config.twitterConsumerSecret,
      '1.0A',
      null,
      'HMAC-SHA1'
    );
    return new MPromise('getTwitterTweet', (resolve, reject) => {
      oauth.get(
        `https://api.twitter.com/1.1/statuses/show.json?id=${twitter_tweet_id}`,
        void 0,
        void 0,
        (err, data, _res) => {
          if (err) {
            logger.error('get twitter tweet failed', err);
            reject(err);
          } else {
            data = JSON.parse(data);
            resolve(data);
          }
        }
      );
    });
  }
  const suspendedOrPotentiallyProblematicTwitterIds = [];
  function getTwitterUserInfoBulk(list_of_twitter_user_id) {
    list_of_twitter_user_id = list_of_twitter_user_id || [];
    const oauth = new OAuth.OAuth(
      'https://api.twitter.com/oauth/request_token',
      'https://api.twitter.com/oauth/access_token',
      Config.twitterConsumerKey,
      Config.twitterConsumerSecret,
      '1.0A',
      null,
      'HMAC-SHA1'
    );
    return new Promise((resolve, reject) => {
      oauth.post(
        'https://api.twitter.com/1.1/users/lookup.json',
        void 0,
        void 0,
        {
          user_id: list_of_twitter_user_id.join(',')
        },
        'multipart/form-data',
        (err, data, _res) => {
          if (err) {
            logger.error('get twitter token failed', err);
            list_of_twitter_user_id.forEach((id) => {
              logger.info(`adding twitter_user_id to suspendedOrPotentiallyProblematicTwitterIds: ${id}`);
              suspendedOrPotentiallyProblematicTwitterIds.push(id);
            });
            reject(err);
          } else {
            data = JSON.parse(data);
            resolve(data);
          }
        }
      );
    });
  }
  function switchToUser(req, res, uid) {
    return new Promise((resolve, reject) => {
      startSession(uid, (errSess, token) => {
        if (errSess) {
          reject(errSess);
          return;
        }
        addCookies(req, res, token, uid)
          .then(() => resolve())
          .catch(() => reject('polis_err_adding_cookies'));
      });
    });
  }
  function retryFunctionWithPromise(f, numTries) {
    return new Promise((resolve, reject) => {
      logger.debug('retryFunctionWithPromise', { numTries });
      f().then(
        (x) => {
          logger.debug('retryFunctionWithPromise RESOLVED');
          resolve(x);
        },
        (err) => {
          numTries -= 1;
          if (numTries <= 0) {
            logger.error('retryFunctionWithPromise REJECTED', err);
            reject(err);
          } else {
            retryFunctionWithPromise(f, numTries).then(resolve, reject);
          }
        }
      );
    });
  }
  function updateSomeTwitterUsers() {
    return pgQueryP_readOnly(
      'select uid, twitter_user_id from twitter_users where modified < (now_as_millis() - 30*60*1000) order by modified desc limit 100;'
    ).then((results) => {
      let twitter_user_ids = _.pluck(results, 'twitter_user_id');
      if (results.length === 0) {
        return [];
      }
      twitter_user_ids = _.difference(twitter_user_ids, suspendedOrPotentiallyProblematicTwitterIds);
      if (twitter_user_ids.length === 0) {
        return [];
      }
      getTwitterUserInfoBulk(twitter_user_ids)
        .then((info) => {
          const updateQueries = info.map((u) => {
            const q =
              'update twitter_users set ' +
              'screen_name = ($2),' +
              'name = ($3),' +
              'followers_count = ($4),' +
              'friends_count = ($5),' +
              'verified = ($6),' +
              'profile_image_url_https = ($7),' +
              'location = ($8),' +
              'modified = now_as_millis() ' +
              'where twitter_user_id = ($1);';
            return pgQueryP(q, [
              u.id,
              u.screen_name,
              u.name,
              u.followers_count,
              u.friends_count,
              u.verified,
              u.profile_image_url_https,
              u.location
            ]);
          });
          return Promise.all(updateQueries);
        })
        .catch((err) => {
          logger.error(`error updating twitter users: ${twitter_user_ids.join(' ')}`, err);
        });
    });
  }
  setInterval(updateSomeTwitterUsers, 1 * 60 * 1000);
  updateSomeTwitterUsers();
  function createUserFromTwitterInfo(o) {
    return createDummyUser().then((uid) =>
      getAndInsertTwitterUser(o, uid).then((result) => {
        const u = result.twitterUser;
        const twitterUserDbRecord = result.twitterUserDbRecord;
        return pgQueryP('update users set hname = ($2) where uid = ($1) and hname is NULL;', [uid, u.name]).then(
          () => twitterUserDbRecord
        );
      })
    );
  }
  function prepForQuoteWithTwitterUser(quote_twitter_screen_name, zid) {
    const query = pgQueryP('select * from twitter_users where screen_name = ($1);', [quote_twitter_screen_name]);
    return addParticipantByTwitterUserId(
      query,
      {
        twitter_screen_name: quote_twitter_screen_name
      },
      zid,
      null
    );
  }
  function prepForTwitterComment(twitter_tweet_id, zid) {
    return getTwitterTweetById(twitter_tweet_id).then((tweet) => {
      const user = tweet.user;
      const twitter_user_id = user.id_str;
      const query = pgQueryP('select * from twitter_users where twitter_user_id = ($1);', [twitter_user_id]);
      return addParticipantByTwitterUserId(
        query,
        {
          twitter_user_id: twitter_user_id
        },
        zid,
        tweet
      );
    });
  }
  function addParticipantByTwitterUserId(query, o, zid, tweet) {
    function addParticipantAndFinish(uid, twitterUser, tweet) {
      return addParticipant(zid, uid).then((rows) => {
        const ptpt = rows[0];
        return {
          ptpt: ptpt,
          twitterUser: twitterUser,
          tweet: tweet
        };
      });
    }
    return query.then((rows) => {
      if (rows?.length) {
        const twitterUser = rows[0];
        const uid = twitterUser.uid;
        return getParticipant(zid, uid)
          .then((ptpt) => {
            if (!ptpt) {
              return addParticipantAndFinish(uid, twitterUser, tweet);
            }
            return {
              ptpt: ptpt,
              twitterUser: twitterUser,
              tweet: tweet
            };
          })
          .catch((_err) => addParticipantAndFinish(uid, twitterUser, tweet));
      }
      return createUserFromTwitterInfo(o).then((twitterUser) => {
        const uid = twitterUser.uid;
        return addParticipant(zid, uid).then((rows) => {
          const ptpt = rows[0];
          return {
            ptpt: ptpt,
            twitterUser: twitterUser,
            tweet: tweet
          };
        });
      });
    });
  }
  const addParticipant = async (zid, uid) => {
    await pgQueryP('INSERT INTO participants_extended (zid, uid) VALUES ($1, $2);', [zid, uid]);
    return pgQueryP('INSERT INTO participants (pid, zid, uid, created) VALUES (NULL, $1, $2, default) RETURNING *;', [
      zid,
      uid
    ]);
  };
  function getAndInsertTwitterUser(o, uid) {
    return getTwitterUserInfo(o, false).then((userString) => {
      const u = JSON.parse(userString)[0];
      return pgQueryP(
        'insert into twitter_users (' +
          'uid,' +
          'twitter_user_id,' +
          'screen_name,' +
          'name,' +
          'followers_count,' +
          'friends_count,' +
          'verified,' +
          'profile_image_url_https,' +
          'location,' +
          'response' +
          ') VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning *;',
        [
          uid,
          u.id,
          u.screen_name,
          u.name,
          u.followers_count,
          u.friends_count,
          u.verified,
          u.profile_image_url_https,
          u.location,
          JSON.stringify(u)
        ]
      ).then((rows) => {
        const record = (rows?.length && rows[0]) || null;
        return {
          twitterUser: u,
          twitterUserDbRecord: record
        };
      });
    });
  }
  function handle_GET_twitter_oauth_callback(req, res) {
    const uid = req.p.uid;
    const dest = req.p.dest;
    function tryGettingTwitterAccessToken() {
      return getTwitterAccessToken({
        oauth_verifier: req.p.oauth_verifier,
        oauth_token: req.p.oauth_token
      });
    }
    retryFunctionWithPromise(tryGettingTwitterAccessToken, 20)
      .then(
        (o) => {
          const pairs = o.split('&');
          const kv = {};
          pairs.forEach((pair) => {
            const pairSplit = pair.split('=');
            const k = pairSplit[0];
            const v = pairSplit[1];
            kv[k] = v;
          });
          getTwitterUserInfo(
            {
              twitter_user_id: kv.user_id
            },
            false
          )
            .then(
              (userStringPayload) => {
                const u = JSON.parse(userStringPayload)[0];
                return pgQueryP(
                  'insert into twitter_users (' +
                    'uid,' +
                    'twitter_user_id,' +
                    'screen_name,' +
                    'name,' +
                    'followers_count,' +
                    'friends_count,' +
                    'verified,' +
                    'profile_image_url_https,' +
                    'location,' +
                    'response' +
                    ') VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);',
                  [
                    uid,
                    u.id,
                    u.screen_name,
                    u.name,
                    u.followers_count,
                    u.friends_count,
                    u.verified,
                    u.profile_image_url_https,
                    u.location,
                    JSON.stringify(u)
                  ]
                ).then(
                  () => {
                    pgQueryP('update users set hname = ($2) where uid = ($1) and hname is NULL;', [uid, u.name])
                      .then(
                        () => {
                          u.uid = uid;
                          res.redirect(dest);
                        },
                        (err) => {
                          fail(res, 500, 'polis_err_twitter_auth_update', err);
                        }
                      )
                      .catch((err) => {
                        fail(res, 500, 'polis_err_twitter_auth_update_misc', err);
                      });
                  },
                  (err) => {
                    if (isDuplicateKey(err)) {
                      Promise.all([
                        pgQueryP('select * from twitter_users where uid = ($1);', [uid]),
                        pgQueryP('select * from twitter_users where twitter_user_id = ($1);', [u.id])
                      ]).then((foo) => {
                        const recordForUid = foo[0][0];
                        const recordForTwitterId = foo[1][0];
                        if (recordForUid && recordForTwitterId) {
                          if (recordForUid.uid === recordForTwitterId.uid) {
                            res.redirect(dest);
                          } else {
                            switchToUser(req, res, recordForTwitterId.uid)
                              .then(() => {
                                res.redirect(dest);
                              })
                              .catch((err) => {
                                fail(res, 500, 'polis_err_twitter_auth_456', err);
                              });
                          }
                        } else if (recordForUid) {
                          fail(res, 500, 'polis_err_twitter_already_attached', err);
                        } else if (recordForTwitterId) {
                          switchToUser(req, res, recordForTwitterId.uid)
                            .then(() => {
                              res.redirect(dest);
                            })
                            .catch((err) => {
                              fail(res, 500, 'polis_err_twitter_auth_234', err);
                            });
                        } else {
                          fail(res, 500, 'polis_err_twitter_auth_345');
                        }
                      });
                    } else {
                      fail(res, 500, 'polis_err_twitter_auth_05', err);
                    }
                  }
                );
              },
              (err) => {
                fail(res, 500, 'polis_err_twitter_auth_041', err);
              }
            )
            .catch((err) => {
              fail(res, 500, 'polis_err_twitter_auth_04', err);
            });
        },
        (err) => {
          fail(res, 500, 'polis_err_twitter_auth_gettoken', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_twitter_auth_misc', err);
      });
  }
  function getSocialParticipantsForMod_timed(zid, limit, mod, convOwner) {
    const _start = Date.now();
    return getSocialParticipantsForMod.apply(null, [zid, limit, mod, convOwner]).then((results) => results);
  }
  function getSocialParticipantsForMod(zid, limit, mod, owner) {
    let modClause = '';
    const params = [zid, limit, owner];
    if (!_.isUndefined(mod)) {
      modClause = ' and mod = ($4)';
      params.push(mod);
    }
    const q = `with p as (select uid, pid, mod from participants where zid = ($1) ${modClause}), final_set as (select * from p limit ($2)), xids_subset as (select * from xids where owner = ($3) and x_profile_image_url is not null), all_rows as (select final_set.mod, twitter_users.twitter_user_id as tw__twitter_user_id, twitter_users.screen_name as tw__screen_name, twitter_users.name as tw__name, twitter_users.followers_count as tw__followers_count, twitter_users.verified as tw__verified, twitter_users.profile_image_url_https as tw__profile_image_url_https, twitter_users.location as tw__location, facebook_users.fb_user_id as fb__fb_user_id, facebook_users.fb_name as fb__fb_name, facebook_users.fb_link as fb__fb_link, facebook_users.fb_public_profile as fb__fb_public_profile, facebook_users.location as fb__location, xids_subset.x_profile_image_url as x_profile_image_url, xids_subset.xid as xid, xids_subset.x_name as x_name, final_set.pid from final_set left join twitter_users on final_set.uid = twitter_users.uid left join facebook_users on final_set.uid = facebook_users.uid left join xids_subset on final_set.uid = xids_subset.uid ) select * from all_rows where (tw__twitter_user_id is not null) or (fb__fb_user_id is not null) or (xid is not null) ;`;
    return pgQueryP(q, params);
  }
  const socialParticipantsCache = new LruCache({
    maxAge: 1000 * 30,
    max: 999
  });
  function getSocialParticipants(zid, uid, limit, mod, math_tick, authorUids) {
    const cacheKey = [zid, limit, mod, math_tick].join('_');
    if (socialParticipantsCache.get(cacheKey)) {
      return socialParticipantsCache.get(cacheKey);
    }
    const authorsQueryParts = (authorUids || []).map(
      (authorUid) => `select ${Number(authorUid)} as uid, 900 as priority`
    );
    let authorsQuery = `(${authorsQueryParts.join(' union ')})`;
    if (!authorUids || authorUids.length === 0) {
      authorsQuery = null;
    }
    const q = `with p as (select uid, pid, mod from participants where zid = ($1) and vote_count >= 1), xids_subset as (select * from xids where owner in (select org_id from conversations where zid = ($1)) and x_profile_image_url is not null), xid_ptpts as (select p.uid, 100 as priority from p inner join xids_subset on xids_subset.uid = p.uid where p.mod >= ($4)), twitter_ptpts as (select p.uid, 10 as priority from p inner join twitter_users  on twitter_users.uid  = p.uid where p.mod >= ($4)), all_fb_users as (select p.uid,   9 as priority from p inner join facebook_users on facebook_users.uid = p.uid where p.mod >= ($4)), self as (select CAST($2 as INTEGER) as uid, 1000 as priority), ${authorsQuery ? `authors as ${authorsQuery}, ` : ''}pptpts as (select prioritized_ptpts.uid, max(prioritized_ptpts.priority) as priority from ( select * from self ${authorsQuery ? 'union ' + 'select * from authors ' : ''}union select * from twitter_ptpts union select * from all_fb_users union select * from xid_ptpts ) as prioritized_ptpts inner join p on prioritized_ptpts.uid = p.uid group by prioritized_ptpts.uid order by priority desc, prioritized_ptpts.uid asc), mod_pptpts as (select asdfasdjfioasjdfoi.uid, max(asdfasdjfioasjdfoi.priority) as priority from ( select * from pptpts union all select uid, 999 as priority from p where mod >= 2) as asdfasdjfioasjdfoi group by asdfasdjfioasjdfoi.uid order by priority desc, asdfasdjfioasjdfoi.uid asc), final_set as (select * from mod_pptpts limit ($3) ) select final_set.priority, twitter_users.twitter_user_id as tw__twitter_user_id, twitter_users.screen_name as tw__screen_name, twitter_users.name as tw__name, twitter_users.followers_count as tw__followers_count, twitter_users.verified as tw__verified, twitter_users.location as tw__location, facebook_users.fb_user_id as fb__fb_user_id, facebook_users.fb_name as fb__fb_name, facebook_users.fb_link as fb__fb_link, facebook_users.fb_public_profile as fb__fb_public_profile, facebook_users.location as fb__location, xids_subset.x_profile_image_url as x_profile_image_url, xids_subset.xid as xid, xids_subset.x_name as x_name, xids_subset.x_email as x_email, p.pid from final_set left join twitter_users on final_set.uid = twitter_users.uid left join facebook_users on final_set.uid = facebook_users.uid left join xids_subset on final_set.uid = xids_subset.uid left join p on final_set.uid = p.uid ;`;
    return pgQueryP_metered_readOnly('getSocialParticipants', q, [zid, uid, limit, mod]).then((response) => {
      socialParticipantsCache.set(cacheKey, response);
      return response;
    });
  }
  const _getSocialInfoForUsers = User.getSocialInfoForUsers;
  function updateVoteCount(zid, pid) {
    return pgQueryP(
      'update participants set vote_count = (select count(*) from votes where zid = ($1) and pid = ($2)) where zid = ($1) and pid = ($2)',
      [zid, pid]
    );
  }
  const votesForZidPidCache = new LruCache({
    max: 5000
  });
  function getVotesForZidPidWithTimestampCheck(zid, pid, math_tick) {
    const key = `${zid}_${pid}`;
    const cachedVotes = votesForZidPidCache.get(key);
    if (cachedVotes) {
      const pair = cachedVotes.split(':');
      const cachedTime = Number(pair[0]);
      const votes = pair[1];
      if (cachedTime >= math_tick) {
        return votes;
      }
    }
    return null;
  }
  function cacheVotesForZidPidWithTimestamp(zid, pid, math_tick, votes) {
    const key = `${zid}_${pid}`;
    const val = `${math_tick}:${votes}`;
    votesForZidPidCache.set(key, val);
  }
  function getVotesForZidPidsWithTimestampCheck(zid, pids, math_tick) {
    let cachedVotes = pids.map((pid) => ({
      pid: pid,
      votes: getVotesForZidPidWithTimestampCheck(zid, pid, math_tick)
    }));
    const uncachedPids = cachedVotes.filter((o) => !o.votes).map((o) => o.pid);
    cachedVotes = cachedVotes.filter((o) => !!o.votes);
    function toObj(items) {
      const o = {};
      for (let i = 0; i < items.length; i++) {
        o[items[i].pid] = items[i].votes;
      }
      return o;
    }
    if (uncachedPids.length === 0) {
      return Promise.resolve(toObj(cachedVotes));
    }
    return getVotesForPids(zid, uncachedPids).then((votesRows) => {
      const newPidToVotes = aggregateVotesToPidVotesObj(votesRows);
      _.each(newPidToVotes, (votes, pid) => {
        cacheVotesForZidPidWithTimestamp(zid, pid, math_tick, votes);
      });
      const cachedPidToVotes = toObj(cachedVotes);
      return Object.assign(newPidToVotes, cachedPidToVotes);
    });
  }
  function getVotesForPids(zid, pids) {
    if (pids.length === 0) {
      return Promise.resolve([]);
    }
    return pgQueryP_readOnly(
      `select * from votes where zid = ($1) and pid in (${pids.join(',')}) order by pid, tid, created;`,
      [zid]
    ).then((votesRows) => {
      for (let i = 0; i < votesRows.length; i++) {
        votesRows[i].weight = votesRows[i].weight / 32767;
      }
      return votesRows;
    });
  }
  function createEmptyVoteVector(greatestTid) {
    const a = [];
    for (let i = 0; i <= greatestTid; i++) {
      a[i] = 'u';
    }
    return a;
  }
  function aggregateVotesToPidVotesObj(votes) {
    let i = 0;
    let greatestTid = 0;
    for (i = 0; i < votes.length; i++) {
      if (votes[i].tid > greatestTid) {
        greatestTid = votes[i].tid;
      }
    }
    const vectors = {};
    for (i = 0; i < votes.length; i++) {
      const v = votes[i];
      vectors[v.pid] = vectors[v.pid] || createEmptyVoteVector(greatestTid);
      const vote = v.vote;
      if (polisTypes.reactions.push === vote) {
        vectors[v.pid][v.tid] = 'd';
      } else if (polisTypes.reactions.pull === vote) {
        vectors[v.pid][v.tid] = 'a';
      } else if (polisTypes.reactions.pass === vote) {
        vectors[v.pid][v.tid] = 'p';
      } else {
        logger.error('unknown vote value');
      }
    }
    const vectors2 = {};
    _.each(vectors, (val, key) => {
      vectors2[key] = val.join('');
    });
    return vectors2;
  }
  function getLocationsForParticipants(zid) {
    return pgQueryP_readOnly('select * from participant_locations where zid = ($1);', [zid]);
  }
  function getPidsForGid(zid, gid, math_tick) {
    return Promise.all([getPca(zid, math_tick), getBidIndexToPidMapping(zid, math_tick)]).then((o) => {
      if (!o[0] || !o[0].asPOJO) {
        return [];
      }
      o[0] = o[0].asPOJO;
      const clusters = o[0]['group-clusters'];
      const indexToBid = o[0]['base-clusters'].id;
      const bidToIndex = [];
      for (let i = 0; i < indexToBid.length; i++) {
        bidToIndex[indexToBid[i]] = i;
      }
      const indexToPids = o[1].bidToPid;
      const cluster = clusters[gid];
      if (!cluster) {
        return [];
      }
      const members = cluster.members;
      let pids = [];
      for (let i = 0; i < members.length; i++) {
        const bid = members[i];
        const index = bidToIndex[bid];
        const morePids = indexToPids[index];
        Array.prototype.push.apply(pids, morePids);
      }
      pids = pids.map((x) => Number.parseInt(x));
      pids.sort((a, b) => a - b);
      return pids;
    });
  }
  function geoCodeWithGoogleApi(locationString) {
    const googleApiKey = process.env.GOOGLE_API_KEY;
    const address = encodeURI(locationString);
    return new Promise((resolve, reject) => {
      request
        .get(`https://maps.googleapis.com/maps/api/geocode/json?address=${address}&key=${googleApiKey}`)
        .then((response) => {
          response = JSON.parse(response);
          if (response.status !== 'OK') {
            reject('polis_err_geocoding_failed');
            return;
          }
          const bestResult = response.results[0];
          resolve(bestResult);
        }, reject)
        .catch(reject);
    });
  }
  function geoCode(locationString) {
    return geoCodeWithGoogleApi(locationString).then((result) => {
      const lat = result.geometry.location.lat;
      const lng = result.geometry.location.lng;
      const o = {
        lat: lat,
        lng: lng
      };
      return o;
    });
  }
  const twitterShareCountCache = LruCache({
    maxAge: 1000 * 60 * 30,
    max: 999
  });
  function getTwitterShareCountForConversation(conversation_id) {
    const cached = twitterShareCountCache.get(conversation_id);
    if (cached) {
      return Promise.resolve(cached);
    }
    const httpUrl = `https://cdn.api.twitter.com/1/urls/count.json?url=http://pol.is/${conversation_id}`;
    const httpsUrl = `https://cdn.api.twitter.com/1/urls/count.json?url=https://pol.is/${conversation_id}`;
    return Promise.all([request.get(httpUrl), request.get(httpsUrl)]).then((a) => {
      const httpResult = a[0];
      const httpsResult = a[1];
      const httpCount = JSON.parse(httpResult).count;
      const httpsCount = JSON.parse(httpsResult).count;
      if (httpCount > 0 && httpsCount > 0 && httpCount === httpsCount) {
        logger.warn(
          'found matching http and https twitter share counts, if this is common, check twitter api to see if it has changed.'
        );
      }
      const count = httpCount + httpsCount;
      twitterShareCountCache.set(conversation_id, count);
      return count;
    });
  }
  const fbShareCountCache = LruCache({
    maxAge: 1000 * 60 * 30,
    max: 999
  });
  function getFacebookShareCountForConversation(conversation_id) {
    const cached = fbShareCountCache.get(conversation_id);
    if (cached) {
      return Promise.resolve(cached);
    }
    const url = `http://graph.facebook.com/?id=https://pol.is/${conversation_id}`;
    return request.get(url).then((result) => {
      const shares = JSON.parse(result).shares;
      fbShareCountCache.set(conversation_id, shares);
      return shares;
    });
  }
  function getParticipantDemographicsForConversation(zid) {
    return pgQueryP(
      'select * from demographic_data left join participants on participants.uid = demographic_data.uid where zid = ($1);',
      [zid]
    );
  }
  function getParticipantVotesForCommentsFlaggedWith_is_meta(zid) {
    return pgQueryP(
      'select tid, pid, vote from votes_latest_unique where zid = ($1) and tid in (select tid from comments where zid = ($1) and is_meta = true)',
      [zid]
    );
  }
  function handle_GET_groupDemographics(req, res) {
    const zid = req.p.zid;
    Promise.all([
      getPidsForGid(zid, 0, -1),
      getPidsForGid(zid, 1, -1),
      getPidsForGid(zid, 2, -1),
      getPidsForGid(zid, 3, -1),
      getPidsForGid(zid, 4, -1),
      getParticipantDemographicsForConversation(zid),
      getParticipantVotesForCommentsFlaggedWith_is_meta(zid),
      isModerator(req.p.zid, req.p.uid)
    ])
      .then((o) => {
        const groupPids = [];
        const groupStats = [];
        let meta = o[5];
        const metaVotes = o[6];
        const isMod = o[7];
        const isReportQuery = !_.isUndefined(req.p.rid);
        if (!isMod && !isReportQuery) {
          throw 'polis_err_groupDemographics_auth';
        }
        for (let i = 0; i < 5; i++) {
          if (o[i]?.length) {
            groupPids.push(o[i]);
            groupStats.push({
              gid: i,
              count: 0,
              gender_male: 0,
              gender_female: 0,
              gender_null: 0,
              birth_year: 0,
              birth_year_count: 0,
              meta_comment_agrees: {},
              meta_comment_disagrees: {},
              meta_comment_passes: {}
            });
          } else {
            break;
          }
        }
        meta = _.indexBy(meta, 'pid');
        const pidToMetaVotes = _.groupBy(metaVotes, 'pid');
        for (let i = 0; i < groupStats.length; i++) {
          const s = groupStats[i];
          const pids = groupPids[i];
          for (let p = 0; p < pids.length; p++) {
            const pid = pids[p];
            const ptptMeta = meta[pid];
            if (ptptMeta) {
              s.count += 1;
              let gender = null;
              if (_.isNumber(ptptMeta.fb_gender)) {
                gender = ptptMeta.fb_gender;
              } else if (_.isNumber(ptptMeta.gender_guess)) {
                gender = ptptMeta.gender_guess;
              } else if (_.isNumber(ptptMeta.ms_gender_estimate_fb)) {
                gender = ptptMeta.ms_gender_estimate_fb;
              }
              if (gender === 0) {
                s.gender_male += 1;
              } else if (gender === 1) {
                s.gender_female += 1;
              } else {
                s.gender_null += 1;
              }
              let birthYear = null;
              if (ptptMeta.ms_birth_year_estimate_fb > 1900) {
                birthYear = ptptMeta.ms_birth_year_estimate_fb;
              } else if (ptptMeta.birth_year_guess > 1900) {
                birthYear = ptptMeta.birth_year_guess;
              }
              if (birthYear > 1900) {
                s.birth_year += birthYear;
                s.birth_year_count += 1;
              }
            }
            const ptptMetaVotes = pidToMetaVotes[pid];
            if (ptptMetaVotes) {
              for (let v = 0; v < ptptMetaVotes.length; v++) {
                const vote = ptptMetaVotes[v];
                if (vote.vote === polisTypes.reactions.pass) {
                  s.meta_comment_passes[vote.tid] = 1 + (s.meta_comment_passes[vote.tid] || 0);
                } else if (vote.vote === polisTypes.reactions.pull) {
                  s.meta_comment_agrees[vote.tid] = 1 + (s.meta_comment_agrees[vote.tid] || 0);
                } else if (vote.vote === polisTypes.reactions.push) {
                  s.meta_comment_disagrees[vote.tid] = 1 + (s.meta_comment_disagrees[vote.tid] || 0);
                }
              }
            }
          }
          s.ms_birth_year_estimate_fb = s.ms_birth_year_estimate_fb / s.ms_birth_year_count;
          s.birth_year_guess = s.birth_year_guess / s.birth_year_guess_count;
          s.birth_year = s.birth_year / s.birth_year_count;
        }
        res.json(groupStats);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_groupDemographics', err);
      });
  }
  function handle_GET_locations(req, res) {
    const zid = req.p.zid;
    const gid = req.p.gid;
    Promise.all([getPidsForGid(zid, gid, -1), getLocationsForParticipants(zid)])
      .then((o) => {
        const pids = o[0];
        let locations = o[1];
        locations = locations.filter((locData) => {
          const pidIsInGroup = _.indexOf(pids, locData.pid, true) >= 0;
          return pidIsInGroup;
        });
        locations = locations.map((locData) => ({
          lat: locData.lat,
          lng: locData.lng,
          n: 1
        }));
        res.status(200).json(locations);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_locations_01', err);
      });
  }
  function removeNullOrUndefinedProperties(o) {
    for (const k in o) {
      const v = o[k];
      if (v === null || v === undefined) {
        delete o[k];
      }
    }
    return o;
  }
  function pullXInfoIntoSubObjects(ptptoiRecord) {
    const p = ptptoiRecord;
    if (p.x_profile_image_url || p.xid || p.x_email) {
      p.xInfo = {};
      p.xInfo.x_profile_image_url = p.x_profile_image_url;
      p.xInfo.xid = p.xid;
      p.xInfo.x_name = p.x_name;
      p.x_profile_image_url = undefined;
      p.xid = undefined;
      p.x_name = undefined;
      p.x_email = undefined;
    }
    return p;
  }
  function pullFbTwIntoSubObjects(ptptoiRecord) {
    const p = ptptoiRecord;
    const x = {};
    _.each(p, (val, key) => {
      const fbMatch = /fb__(.*)/.exec(key);
      const twMatch = /tw__(.*)/.exec(key);
      if (fbMatch && fbMatch.length === 2 && val !== null) {
        x.facebook = x.facebook || {};
        x.facebook[fbMatch[1]] = val;
      } else if (twMatch && twMatch.length === 2 && val !== null) {
        x.twitter = x.twitter || {};
        x.twitter[twMatch[1]] = val;
      } else {
        x[key] = val;
      }
    });
    if (x.facebook?.fb_public_profile) {
      try {
        const temp = JSON.parse(x.facebook.fb_public_profile);
        x.facebook.verified = temp.verified;
        x.facebook.fb_public_profile = undefined;
      } catch (err) {
        logger.error(`error parsing JSON of fb_public_profile for uid: ${p.uid}`, err);
      }
      if (!_.isUndefined(x.facebook.fb_user_id)) {
        const width = 40;
        const height = 40;
        x.facebook.fb_picture = `https://graph.facebook.com/v2.2/${x.facebook.fb_user_id}/picture?width=${width}&height=${height}`;
      }
    }
    return x;
  }
  function handle_PUT_ptptois(req, res) {
    const zid = req.p.zid;
    const uid = req.p.uid;
    const pid = req.p.pid;
    const mod = req.p.mod;
    isModerator(zid, uid)
      .then((isMod) => {
        if (!isMod) {
          fail(res, 403, 'polis_err_ptptoi_permissions_123');
          return;
        }
        return pgQueryP('update participants set mod = ($3) where zid = ($1) and pid = ($2);', [zid, pid, mod]).then(
          () => {
            res.status(200).json({});
          }
        );
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_ptptoi_misc_234', err);
      });
  }
  function handle_GET_ptptois(req, res) {
    const zid = req.p.zid;
    const mod = req.p.mod;
    const uid = req.p.uid;
    const limit = 99999;
    const convPromise = getConversationInfo(req.p.zid);
    const socialPtptsPromise = convPromise.then((conv) => {
      return getSocialParticipantsForMod_timed(zid, limit, mod, conv.owner);
    });
    Promise.all([socialPtptsPromise, getConversationInfo(zid)])
      .then((a) => {
        let ptptois = a[0];
        const conv = a[1];
        const isOwner = uid === conv.owner;
        const isAllowed = isOwner || isPolisDev(req.p.uid) || conv.is_data_open;
        if (isAllowed) {
          ptptois = ptptois.map(pullXInfoIntoSubObjects);
          ptptois = ptptois.map(removeNullOrUndefinedProperties);
          ptptois = ptptois.map(pullFbTwIntoSubObjects);
          ptptois = ptptois.map((p) => {
            p.conversation_id = req.p.conversation_id;
            return p;
          });
        } else {
          ptptois = [];
        }
        res.status(200).json(ptptois);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_ptptoi_misc', err);
      });
  }
  function handle_GET_votes_famous(req, res) {
    doFamousQuery(req.p, req)
      .then(
        (data) => {
          res.status(200).json(data);
        },
        (err) => {
          fail(res, 500, 'polis_err_famous_proj_get2', err);
        }
      )
      .catch((err) => {
        fail(res, 500, 'polis_err_famous_proj_get1', err);
      });
  }
  function doFamousQuery(o, req) {
    const uid = o?.uid;
    const zid = o?.zid;
    const math_tick = o?.math_tick;
    const hardLimit = _.isUndefined(o?.ptptoiLimit) ? 30 : o?.ptptoiLimit;
    const mod = 0;
    function getAuthorUidsOfFeaturedComments() {
      return getPca(zid, 0).then((pcaResult) => {
        if (!pcaResult || typeof pcaResult !== 'object' || pcaResult === null || !('asPOJO' in pcaResult)) {
          return [];
        }
        const pcaData = pcaResult.asPOJO;
        pcaData.consensus = pcaData.consensus || {};
        pcaData.consensus.agree = pcaData.consensus.agree || [];
        pcaData.consensus.disagree = pcaData.consensus.disagree || [];
        const consensusTids = _.union(
          _.pluck(pcaData.consensus.agree, 'tid'),
          _.pluck(pcaData.consensus.disagree, 'tid')
        );
        let groupTids = [];
        for (const gid in pcaData.repness) {
          const commentData = pcaData.repness[gid];
          groupTids = _.union(groupTids, _.pluck(commentData, 'tid'));
        }
        let featuredTids = _.union(consensusTids, groupTids);
        featuredTids.sort();
        featuredTids = _.uniq(featuredTids);
        if (featuredTids.length === 0) {
          return [];
        }
        const q = `with authors as (select distinct(uid) from comments where zid = ($1) and tid in (${featuredTids.join(',')}) order by uid) select authors.uid from authors inner join facebook_users on facebook_users.uid = authors.uid union select authors.uid from authors inner join twitter_users on twitter_users.uid = authors.uid union select authors.uid from authors inner join xids on xids.uid = authors.uid order by uid;`;
        return pgQueryP_readOnly(q, [zid]).then((comments) => {
          let uids = _.pluck(comments, 'uid');
          uids = _.uniq(uids);
          return uids;
        });
      });
    }
    return Promise.all([getConversationInfo(zid), getAuthorUidsOfFeaturedComments()]).then((a) => {
      const conv = a[0];
      const authorUids = a[1];
      if (conv.is_anon) {
        return {};
      }
      return Promise.all([getSocialParticipants(zid, uid, hardLimit, mod, math_tick, authorUids)]).then((stuff) => {
        let participantsWithSocialInfo = stuff[0] || [];
        participantsWithSocialInfo = participantsWithSocialInfo.map((p) => {
          let x = pullXInfoIntoSubObjects(p);
          x = pullFbTwIntoSubObjects(x);
          if (p.priority === 1000) {
            x.isSelf = true;
          }
          if (x.twitter) {
            x.twitter.profile_image_url_https = `${getServerNameWithProtocol(req)}/twitter_image?id=${x.twitter.twitter_user_id}`;
          }
          return x;
        });
        let pids = participantsWithSocialInfo.map((p) => p.pid);
        const pidToData = _.indexBy(participantsWithSocialInfo, 'pid');
        pids.sort((a, b) => a - b);
        pids = _.uniq(pids, true);
        return getVotesForZidPidsWithTimestampCheck(zid, pids, math_tick).then((vectors) =>
          getBidsForPids(zid, -1, pids).then(
            (pidsToBids) => {
              _.each(vectors, (value, pid, _list) => {
                pid = Number.parseInt(pid);
                const bid = pidsToBids[pid];
                const notInBucket = _.isUndefined(bid);
                const isSelf = pidToData[pid].isSelf;
                if (notInBucket && !isSelf) {
                  delete pidToData[pid];
                } else if (pidToData[pid]) {
                  pidToData[pid].votes = value;
                  pidToData[pid].bid = bid;
                }
              });
              return pidToData;
            },
            (_err) => ({})
          )
        );
      });
    });
  }
  function handle_GET_twitter_users(req, res) {
    const uid = req.p.uid;
    let p;
    if (uid) {
      p = pgQueryP_readOnly('select * from twitter_users where uid = ($1);', [uid]);
    } else if (req.p.twitter_user_id) {
      p = pgQueryP_readOnly('select * from twitter_users where twitter_user_id = ($1);', [req.p.twitter_user_id]);
    } else {
      fail(res, 401, 'polis_err_missing_uid_or_twitter_user_id');
      return;
    }
    p.then((data) => {
      data = data[0];
      data.profile_image_url_https = `${getServerNameWithProtocol(req)}/twitter_image?id=${data.twitter_user_id}`;
      res.status(200).json(data);
    }).catch((err) => {
      fail(res, 500, 'polis_err_twitter_user_info_get', err);
    });
  }
  function doSendEinvite(req, email) {
    return generateTokenP(30, false).then((einvite) =>
      pgQueryP('insert into einvites (email, einvite) values ($1, $2);', [email, einvite]).then((_rows) =>
        sendEinviteEmail(req, email, einvite)
      )
    );
  }
  function handle_POST_einvites(req, res) {
    const email = req.p.email;
    doSendEinvite(req, email)
      .then(() => {
        res.status(200).json({});
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_sending_einvite', err);
      });
  }
  function handle_GET_einvites(req, res) {
    const einvite = req.p.einvite;
    pgQueryP('select * from einvites where einvite = ($1);', [einvite])
      .then((rows) => {
        if (!rows.length) {
          throw new Error('polis_err_missing_einvite');
        }
        res.status(200).json(rows[0]);
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_fetching_einvite', err);
      });
  }
  function handle_POST_contributors(req, res) {
    const uid = req.p.uid || null;
    const agreement_version = req.p.agreement_version;
    const name = req.p.name;
    const email = req.p.email;
    const github_id = req.p.github_id;
    const company_name = req.p.company_name;
    pgQueryP(
      'insert into contributor_agreement_signatures (uid, agreement_version, github_id, name, email, company_name) ' +
        'values ($1, $2, $3, $4, $5, $6);',
      [uid, agreement_version, github_id, name, email, company_name]
    ).then(
      () => {
        emailTeam(
          'contributer agreement signed',
          [uid, agreement_version, github_id, name, email, company_name].join('\n')
        );
        res.json({});
      },
      (err) => {
        fail(res, 500, 'polis_err_POST_contributors_misc', err);
      }
    );
  }
  function generateSingleUseUrl(req, conversation_id, suzinvite) {
    return `${getServerNameWithProtocol(req)}/ot/${conversation_id}/${suzinvite}`;
  }
  function buildConversationUrl(req, zinvite) {
    return `${getServerNameWithProtocol(req)}/${zinvite}`;
  }
  function buildConversationDemoUrl(req, zinvite) {
    return `${getServerNameWithProtocol(req)}/demo/${zinvite}`;
  }
  function buildModerationUrl(req, zinvite) {
    return `${getServerNameWithProtocol(req)}/m/${zinvite}`;
  }
  function buildSeedUrl(req, zinvite) {
    return `${buildModerationUrl(req, zinvite)}/comments/seed`;
  }
  function getConversationUrl(req, zid, dontUseCache) {
    return getZinvite(zid, dontUseCache).then((zinvite) => buildConversationUrl(req, zinvite));
  }
  function createOneSuzinvite(xid, zid, owner, generateSingleUseUrl) {
    return generateSUZinvites(1).then((suzinviteArray) => {
      const suzinvite = suzinviteArray[0];
      return pgQueryP('INSERT INTO suzinvites (suzinvite, xid, zid, owner) VALUES ($1, $2, $3, $4);', [
        suzinvite,
        xid,
        zid,
        owner
      ])
        .then((_result) => getZinvite(zid))
        .then((conversation_id) => ({
          zid: zid,
          conversation_id: conversation_id
        }))
        .then((o) => ({
          zid: o.zid,
          conversation_id: o.conversation_id,
          suurl: generateSingleUseUrl(o.conversation_id, suzinvite)
        }));
    });
  }
  function handle_GET_testConnection(_req, res) {
    res.status(200).json({
      status: 'ok'
    });
  }
  function handle_GET_testDatabase(_req, res) {
    pgQueryP('select uid from users limit 1', []).then(
      (_rows) => {
        res.status(200).json({
          status: 'ok'
        });
      },
      (err) => {
        fail(res, 500, 'polis_err_testDatabase', err);
      }
    );
  }
  function sendSuzinviteEmail(req, email, conversation_id, suzinvite) {
    const serverName = getServerNameWithProtocol(req);
    const body = `Welcome to pol.is!\n\nClick this link to open your account:\n\n${serverName}/ot/${conversation_id}/${suzinvite}\n\nThank you for using Polis\n`;
    return sendTextEmail(polisFromAddress, email, 'Join the pol.is conversation!', body);
  }
  function addInviter(inviter_uid, invited_email) {
    return pgQueryP('insert into inviters (inviter_uid, invited_email) VALUES ($1, $2);', [inviter_uid, invited_email]);
  }
  function handle_POST_users_invite(req, res) {
    const uid = req.p.uid;
    const emails = req.p.emails;
    const zid = req.p.zid;
    const conversation_id = req.p.conversation_id;
    getConversationInfo(zid)
      .then((conv) => {
        const owner = conv.owner;
        generateSUZinvites(emails.length)
          .then((suzinviteArray) => {
            const pairs = _.zip(emails, suzinviteArray);
            const valuesStatements = pairs.map((pair) => {
              const xid = escapeLiteral(pair[0]);
              const suzinvite = escapeLiteral(pair[1]);
              const statement = `(${suzinvite}, ${xid},${zid},${owner})`;
              return statement;
            });
            const query = `INSERT INTO suzinvites (suzinvite, xid, zid, owner) VALUES ${valuesStatements.join(',')};`;
            pgQuery(query, [], (err, _results) => {
              if (err) {
                fail(res, 500, 'polis_err_saving_invites', err);
                return;
              }
              Promise.all(
                pairs.map((pair) => {
                  const email = pair[0];
                  const suzinvite = pair[1];
                  return sendSuzinviteEmail(req, email, conversation_id, suzinvite).then(
                    () => addInviter(uid, email),
                    (err) => {
                      fail(res, 500, 'polis_err_sending_invite', err);
                    }
                  );
                })
              )
                .then(() => {
                  res.status(200).json({
                    status: ':-)'
                  });
                })
                .catch((err) => {
                  fail(res, 500, 'polis_err_sending_invite', err);
                });
            });
          })
          .catch((err) => {
            fail(res, 500, 'polis_err_generating_invites', err);
          });
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_getting_conversation_info', err);
      });
  }
  function initializeImplicitConversation(site_id, page_id, o) {
    return pgQueryP_readOnly('select uid from users where site_id = ($1) and site_owner = TRUE;', [site_id]).then(
      (rows) => {
        if (!rows || !rows.length) {
          throw new Error('polis_err_bad_site_id');
        }
        return new Promise((resolve, reject) => {
          const uid = rows[0].uid;
          const generateShortUrl = false;
          isUserAllowedToCreateConversations(uid, (err, isAllowed) => {
            if (err) {
              reject(err);
              return;
            }
            if (!isAllowed) {
              reject(err);
              return;
            }
            const params = Object.assign(o, {
              owner: uid,
              org_id: uid,
              is_active: true,
              is_draft: false,
              is_public: true,
              is_anon: false,
              profanity_filter: true,
              spam_filter: true,
              strict_moderation: false,
              owner_sees_participation_stats: false
            });
            const q = sql_conversations.insert(params).returning('*').toString();
            pgQuery(q, [], (err, result) => {
              if (err) {
                if (isDuplicateKey(err)) {
                  logger.error('polis_err_create_implicit_conv_duplicate_key', err);
                  reject('polis_err_create_implicit_conv_duplicate_key');
                } else {
                  reject('polis_err_create_implicit_conv_db');
                }
              }
              const zid = result?.rows?.[0]?.zid;
              Promise.all([registerPageId(site_id, page_id, zid), generateAndRegisterZinvite(zid, generateShortUrl)])
                .then((o) => {
                  const zinvite = o[1];
                  resolve({
                    owner: uid,
                    zid: zid,
                    zinvite: zinvite
                  });
                })
                .catch((err) => {
                  reject('polis_err_zinvite_create_implicit', err);
                });
            });
          });
        });
      }
    );
  }
  function sendImplicitConversationCreatedEmails(site_id, page_id, url, modUrl, seedUrl) {
    const body = `Conversation created!\n\nYou can find the conversation here:\n${url}\nYou can moderate the conversation here:\n${modUrl}\n\nWe recommend you add 2-3 short statements to start things off. These statements should be easy to agree or disagree with. Here are some examples:\n "I think the proposal is good"\n "This topic matters a lot"\n or "The bike shed should have a metal roof"\n\nYou can add statements here:\n${seedUrl}\n\nFeel free to reply to this email if you have questions.\n\nAdditional info: \nsite_id: "${site_id}"\npage_id: "${page_id}"\n\n`;
    return pgQueryP('select email from users where site_id = ($1)', [site_id]).then((rows) => {
      const emails = _.pluck(rows, 'email');
      return sendMultipleTextEmails(polisFromAddress, emails, 'Polis conversation created', body);
    });
  }
  function registerPageId(site_id, page_id, zid) {
    return pgQueryP('insert into page_ids (site_id, page_id, zid) values ($1, $2, $3);', [site_id, page_id, zid]);
  }
  function doGetConversationPreloadInfo(conversation_id) {
    return Conversation.getZidFromConversationId(conversation_id)
      .then((zid) => Promise.all([getConversationInfo(zid)]))
      .then((a) => {
        let conv = a[0];
        const auth_opt_allow_3rdparty = ifDefinedFirstElseSecond(
          conv.auth_opt_allow_3rdparty,
          DEFAULTS.auth_opt_allow_3rdparty
        );
        const auth_opt_fb_computed = false;
        const auth_opt_tw_computed = false;
        conv = {
          topic: conv.topic,
          description: conv.description,
          created: conv.created,
          link_url: conv.link_url,
          parent_url: conv.parent_url,
          vis_type: conv.vis_type,
          write_type: conv.write_type,
          help_type: conv.help_type,
          socialbtn_type: conv.socialbtn_type,
          bgcolor: conv.bgcolor,
          help_color: conv.help_color,
          help_bgcolor: conv.help_bgcolor,
          style_btn: conv.style_btn,
          auth_needed_to_vote: false,
          auth_needed_to_write: false,
          auth_opt_allow_3rdparty: auth_opt_allow_3rdparty,
          auth_opt_fb_computed: auth_opt_fb_computed,
          auth_opt_tw_computed: auth_opt_tw_computed
        };
        conv.conversation_id = conversation_id;
        return conv;
      });
  }
  function handle_GET_conversationPreloadInfo(req, res) {
    return doGetConversationPreloadInfo(req.p.conversation_id).then(
      (conv) => {
        res.status(200).json(conv);
      },
      (err) => {
        fail(res, 500, 'polis_err_get_conversation_preload_info', err);
      }
    );
  }
  function handle_GET_implicit_conversation_generation(req, res) {
    let site_id = /polis_site_id[^\/]*/.exec(req.path) || null;
    let page_id = /\S\/([^\/]*)/.exec(req.path) || null;
    if (!site_id?.length || (page_id && page_id?.length < 2)) {
      fail(res, 404, 'polis_err_parsing_site_id_or_page_id');
    }
    site_id = site_id?.[0];
    page_id = page_id?.[1];
    const demo = req.p.demo;
    const ucv = req.p.ucv;
    const ucw = req.p.ucw;
    const ucsh = req.p.ucsh;
    const ucst = req.p.ucst;
    const ucsd = req.p.ucsd;
    const ucsv = req.p.ucsv;
    const ucsf = req.p.ucsf;
    const ui_lang = req.p.ui_lang;
    const subscribe_type = req.p.subscribe_type;
    const xid = req.p.xid;
    const x_name = req.p.x_name;
    const x_profile_image_url = req.p.x_profile_image_url;
    const x_email = req.p.x_email;
    const parent_url = req.p.parent_url;
    const dwok = req.p.dwok;
    const o = {};
    ifDefinedSet('parent_url', req.p, o);
    ifDefinedSet('auth_opt_allow_3rdparty', req.p, o);
    ifDefinedSet('topic', req.p, o);
    if (!_.isUndefined(req.p.show_vis)) {
      o.vis_type = req.p.show_vis ? 1 : 0;
    }
    if (!_.isUndefined(req.p.bg_white)) {
      o.bgcolor = req.p.bg_white ? '#fff' : null;
    }
    o.socialbtn_type = req.p.show_share ? 1 : 0;
    if (req.p.referrer) {
      setParentReferrerCookie(req, res, req.p.referrer);
    }
    if (req.p.parent_url) {
      setParentUrlCookie(req, res, req.p.parent_url);
    }
    function appendParams(url) {
      url += `?site_id=${site_id}&page_id=${page_id}`;
      if (!_.isUndefined(ucv)) {
        url += `&ucv=${ucv}`;
      }
      if (!_.isUndefined(ucw)) {
        url += `&ucw=${ucw}`;
      }
      if (!_.isUndefined(ucst)) {
        url += `&ucst=${ucst}`;
      }
      if (!_.isUndefined(ucsd)) {
        url += `&ucsd=${ucsd}`;
      }
      if (!_.isUndefined(ucsv)) {
        url += `&ucsv=${ucsv}`;
      }
      if (!_.isUndefined(ucsf)) {
        url += `&ucsf=${ucsf}`;
      }
      if (!_.isUndefined(ui_lang)) {
        url += `&ui_lang=${ui_lang}`;
      }
      if (!_.isUndefined(ucsh)) {
        url += `&ucsh=${ucsh}`;
      }
      if (!_.isUndefined(subscribe_type)) {
        url += `&subscribe_type=${subscribe_type}`;
      }
      if (!_.isUndefined(xid)) {
        url += `&xid=${xid}`;
      }
      if (!_.isUndefined(x_name)) {
        url += `&x_name=${encodeURIComponent(x_name)}`;
      }
      if (!_.isUndefined(x_profile_image_url)) {
        url += `&x_profile_image_url=${encodeURIComponent(x_profile_image_url)}`;
      }
      if (!_.isUndefined(x_email)) {
        url += `&x_email=${encodeURIComponent(x_email)}`;
      }
      if (!_.isUndefined(parent_url)) {
        url += `&parent_url=${encodeURIComponent(parent_url)}`;
      }
      if (!_.isUndefined(dwok)) {
        url += `&dwok=${dwok}`;
      }
      return url;
    }
    pgQueryP_readOnly('select * from page_ids where site_id = ($1) and page_id = ($2);', [site_id, page_id])
      .then((rows) => {
        if (!rows || !rows.length) {
          initializeImplicitConversation(site_id, page_id, o)
            .then((conv) => {
              let url = _.isUndefined(demo)
                ? buildConversationUrl(req, conv.zinvite)
                : buildConversationDemoUrl(req, conv.zinvite);
              const modUrl = buildModerationUrl(req, conv.zinvite);
              const seedUrl = buildSeedUrl(req, conv.zinvite);
              sendImplicitConversationCreatedEmails(site_id, page_id, url, modUrl, seedUrl)
                .then(() => {
                  logger.info('email sent');
                })
                .catch((err) => {
                  logger.error('email fail', err);
                });
              url = appendParams(url);
              res.redirect(url);
            })
            .catch((err) => {
              fail(res, 500, 'polis_err_creating_conv', err);
            });
        } else {
          getZinvite(rows[0].zid)
            .then((conversation_id) => {
              let url = buildConversationUrl(req, conversation_id);
              url = appendParams(url);
              res.redirect(url);
            })
            .catch((err) => {
              fail(res, 500, 'polis_err_finding_conversation_id', err);
            });
        }
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_redirecting_to_conv', err);
      });
  }
  const routingProxy = new httpProxy.createProxyServer();
  function addStaticFileHeaders(res) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', 0);
  }
  function proxy(req, res) {
    const hostname = Config.staticFilesHost;
    if (!hostname) {
      const host = req?.headers?.host || '';
      const re = new RegExp(`${Config.getServerHostname()}$`);
      if (host.match(re)) {
        fail(res, 500, 'polis_err_proxy_serving_to_domain', new Error(host));
      } else {
        fail(res, 500, 'polis_err_proxy_serving_to_domain', new Error(host));
      }
      return;
    }
    if (devMode) {
      addStaticFileHeaders(res);
    }
    const port = Config.staticFilesParticipationPort;
    if (req?.headers?.host) req.headers.host = hostname;
    routingProxy.web(req, res, {
      target: {
        host: hostname,
        port: port
      }
    });
  }
  function makeRedirectorTo(path) {
    return (req, res) => {
      const protocol = devMode ? 'http://' : 'https://';
      const url = protocol + req?.headers?.host + path;
      res.writeHead(302, {
        Location: url
      });
      res.end();
    };
  }
  function fetchThirdPartyCookieTestPt1(_req, res) {
    res.set({ 'Content-Type': 'text/html' });
    res.send(
      Buffer.from(
        '<body>\n' +
          '<script>\n' +
          '  document.cookie="thirdparty=yes; Max-Age=3600; SameSite=None; Secure";\n' +
          '  document.location="thirdPartyCookieTestPt2.html";\n' +
          '</script>\n' +
          '</body>'
      )
    );
  }
  function fetchThirdPartyCookieTestPt2(_req, res) {
    res.set({ 'Content-Type': 'text/html' });
    res.send(
      Buffer.from(
        '<body>\n' +
          '<script>\n' +
          '  if (window.parent) {\n' +
          '   if (/thirdparty=yes/.test(document.cookie)) {\n' +
          "     window.parent.postMessage('MM:3PCsupported', '*');\n" +
          '   } else {\n' +
          "     window.parent.postMessage('MM:3PCunsupported', '*');\n" +
          '   }\n' +
          "   document.cookie = 'thirdparty=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';\n" +
          '  }\n' +
          '</script>\n' +
          '</body>'
      )
    );
  }
  function makeFileFetcher(_hostname, port, path, headers, preloadData) {
    return (req, res) => {
      const hostname = Config.staticFilesHost;
      if (!hostname) {
        fail(res, 500, 'polis_err_file_fetcher_serving_to_domain');
        return;
      }
      const url = `http://${hostname}:${port}${path}`;
      logger.info(`fetch file from ${url}`);
      let x = request(url);
      req.pipe(x);
      if (!_.isUndefined(preloadData)) {
        x = x.pipe(replaceStream('"REPLACE_THIS_WITH_PRELOAD_DATA"', JSON.stringify(preloadData)));
      }
      let fbMetaTagsString = '<meta property="og:image" content="https://s3.amazonaws.com/pol.is/polis_logo.png" />\n';
      if (preloadData?.conversation) {
        fbMetaTagsString += `    <meta property="og:title" content="${encode(preloadData.conversation.topic)}" />\n`;
        fbMetaTagsString += `    <meta property="og:description" content="${encode(preloadData.conversation.description)}" />\n`;
      }
      x = x.pipe(replaceStream('<!-- REPLACE_THIS_WITH_FB_META_TAGS -->', fbMetaTagsString));
      res.set(headers);
      x.pipe(res);
      x.on('error', (err) => {
        fail(res, 500, `polis_err_finding_file ${path}`, err);
      });
    };
  }
  function isUnsupportedBrowser(req) {
    return /MSIE [234567]/.test(req?.headers?.['user-agent'] || '');
  }
  function browserSupportsPushState(req) {
    return !/MSIE [23456789]/.test(req?.headers?.['user-agent'] || '');
  }
  const hostname = Config.staticFilesHost;
  const staticFilesParticipationPort = Config.staticFilesParticipationPort;
  const staticFilesAdminPort = Config.staticFilesAdminPort;
  const fetchUnsupportedBrowserPage = makeFileFetcher(
    hostname,
    staticFilesParticipationPort,
    '/unsupportedBrowser.html',
    {
      'Content-Type': 'text/html'
    }
  );
  function fetchIndex(req, res, preloadData, port) {
    const headers = {
      'Content-Type': 'text/html'
    };
    if (!devMode) {
      Object.assign(headers, {
        'Cache-Control': 'no-cache'
      });
    }
    setCookieTestCookie(req, res);
    const indexPath = '/index.html';
    const doFetch = makeFileFetcher(hostname, port, indexPath, headers, preloadData);
    if (isUnsupportedBrowser(req)) {
      return fetchUnsupportedBrowserPage(req, res);
    }
    if (!browserSupportsPushState(req) && req.path.length > 1 && !/^\/api/.exec(req.path)) {
      res.writeHead(302, {
        Location: `https://${req?.headers?.host}/#${req.path}`
      });
      return res.end();
    }
    return doFetch(req, res);
  }
  function fetchIndexWithoutPreloadData(req, res, port) {
    return fetchIndex(req, res, {}, port);
  }
  function ifDefinedFirstElseSecond(first, second) {
    return _.isUndefined(first) ? second : first;
  }
  const fetch404Page = makeFileFetcher(hostname, staticFilesAdminPort, '/404.html', {
    'Content-Type': 'text/html'
  });
  function fetchIndexForConversation(req, res) {
    logger.debug('fetchIndexForConversation', req.path);
    const match = req.path.match(/[0-9][0-9A-Za-z]+/);
    let conversation_id;
    if (match?.length) {
      conversation_id = match[0];
    }
    setTimeout(() => {
      if (Config.twitterConsumerKey) {
        getTwitterShareCountForConversation(conversation_id).catch((err) => {
          logger.error('polis_err_fetching_twitter_share_count', err);
        });
      }
      if (Config.fbAppId) {
        getFacebookShareCountForConversation(conversation_id).catch((err) => {
          logger.error('polis_err_fetching_facebook_share_count', err);
        });
      }
    }, 100);
    doGetConversationPreloadInfo(conversation_id)
      .then((x) => {
        const preloadData = {
          conversation: x
        };
        fetchIndex(req, res, preloadData, staticFilesParticipationPort);
      })
      .catch((err) => {
        logger.error('polis_err_fetching_conversation_info', err);
        fetch404Page(req, res);
      });
  }
  const fetchIndexForAdminPage = makeFileFetcher(hostname, staticFilesAdminPort, '/index_admin.html', {
    'Content-Type': 'text/html'
  });
  const fetchIndexForReportPage = makeFileFetcher(hostname, staticFilesAdminPort, '/index_report.html', {
    'Content-Type': 'text/html'
  });
  function handle_GET_iip_conversation(req, res) {
    const conversation_id = req.params.conversation_id;
    res.set({
      'Content-Type': 'text/html'
    });
    res.send(`<a href='https://pol.is/${conversation_id}' target='_blank'>${conversation_id}</a>`);
  }
  function handle_GET_iim_conversation(req, res) {
    const zid = req.p.zid;
    const conversation_id = req.params.conversation_id;
    getConversationInfo(zid)
      .then((info) => {
        res.set({
          'Content-Type': 'text/html'
        });
        const title = info.topic || info.created;
        res.send(
          `<a href='https://pol.is/${conversation_id}' target='_blank'>${title}</a><p><a href='https://pol.is/m${conversation_id}' target='_blank'>moderate</a></p>${info.description ? `<p>${info.description}</p>` : ''}`
        );
      })
      .catch((err) => {
        fail(res, 500, 'polis_err_fetching_conversation_info', err);
      });
  }
  function handle_GET_twitter_image(req, res) {
    getTwitterUserInfo(
      {
        twitter_user_id: req.p.id
      },
      true
    )
      .then((data) => {
        const parsedData = JSON.parse(data);
        if (!parsedData || !parsedData.length) {
          fail(res, 500, 'polis_err_finding_twitter_user_info');
          return;
        }
        const url = parsedData[0].profile_image_url;
        let finished = false;
        http
          .get(url, (twitterResponse) => {
            if (!finished) {
              clearTimeout(timeoutHandle);
              finished = true;
              res.setHeader('Cache-Control', 'no-transform,public,max-age=18000,s-maxage=18000');
              twitterResponse.pipe(res);
            }
          })
          .on('error', (err) => {
            finished = true;
            fail(res, 500, `polis_err_finding_file ${url}`, err);
          });
        const timeoutHandle = setTimeout(() => {
          if (!finished) {
            finished = true;
            res.writeHead(504);
            res.end('request timed out');
            logger.debug('twitter_image timeout');
          }
        }, 9999);
      })
      .catch((err) => {
        logger.error('polis_err_missing_twitter_image', err);
        res.status(500).end();
      });
  }
  const handle_GET_conditionalIndexFetcher = (() => (req, res) => {
    if (hasAuthToken(req)) {
      return fetchIndexForAdminPage(req, res);
    }
    if (!browserSupportsPushState(req)) {
      return fetchIndexForAdminPage(req, res);
    }
    const url = `${getServerNameWithProtocol(req)}/home`;
    res.redirect(url);
  })();
  function middleware_log_request_body(req, _res, next) {
    if (devMode) {
      let b = '';
      if (req.body) {
        const temp = _.clone(req.body);
        if (temp.password) {
          temp.password = 'some_password';
        }
        if (temp.newPassword) {
          temp.newPassword = 'some_password';
        }
        if (temp.password2) {
          temp.password2 = 'some_password';
        }
        if (temp.hname) {
          temp.hname = 'somebody';
        }
        if (temp.polisApiKey) {
          temp.polisApiKey = 'pkey_somePolisApiKey';
        }
        b = JSON.stringify(temp);
      }
      logger.debug('middleware_log_request_body', { path: req.path, body: b });
    } else {
    }
    next();
  }
  function middleware_log_middleware_errors(err, _req, _res, next) {
    if (!err) {
      return next();
    }
    logger.error('middleware_log_middleware_errors', err);
    next(err);
  }
  function middleware_check_if_options(req, res, next) {
    if (req.method.toLowerCase() !== 'options') {
      return next();
    }
    return res.send(204);
  }
  const middleware_responseTime_start = responseTime((req, _res, time) => {
    if (req?.route?.path) {
      const path = req.route.path;
      time = Math.trunc(time);
      addInRamMetric(path, time);
    }
  });
  logger.debug('end initializePolisHelpers');
  const returnObject = {
    addCorsHeader,
    auth,
    authOptional,
    COOKIES,
    denyIfNotFromWhitelistedDomain,
    devMode,
    emailTeam,
    enableAgid,
    fail,
    fetchThirdPartyCookieTestPt1,
    fetchThirdPartyCookieTestPt2,
    fetchIndexForAdminPage,
    fetchIndexForConversation,
    fetchIndexForReportPage,
    fetchIndexWithoutPreloadData,
    getPidForParticipant,
    haltOnTimeout,
    HMAC_SIGNATURE_PARAM_NAME,
    hostname,
    makeFileFetcher,
    makeRedirectorTo,
    pidCache,
    staticFilesAdminPort,
    staticFilesParticipationPort,
    proxy,
    redirectIfHasZidButNoConversationId,
    redirectIfNotHttps,
    sendTextEmail,
    timeout,
    writeDefaultHead,
    middleware_check_if_options,
    middleware_log_middleware_errors,
    middleware_log_request_body,
    middleware_responseTime_start,
    handle_DELETE_metadata_answers,
    handle_DELETE_metadata_questions,
    handle_GET_bid,
    handle_GET_bidToPid,
    handle_GET_comments,
    handle_GET_comments_translations,
    handle_GET_conditionalIndexFetcher,
    handle_GET_contexts,
    handle_GET_conversationPreloadInfo,
    handle_GET_conversations,
    handle_GET_conversationsRecentActivity,
    handle_GET_conversationsRecentlyStarted,
    handle_GET_conversationStats,
    handle_GET_math_correlationMatrix,
    handle_GET_dataExport,
    handle_GET_dataExport_results,
    handle_GET_reportExport,
    handle_GET_domainWhitelist,
    handle_GET_dummyButton,
    handle_GET_einvites,
    handle_GET_facebook_delete,
    handle_GET_groupDemographics,
    handle_GET_iim_conversation,
    handle_GET_iip_conversation,
    handle_GET_implicit_conversation_generation,
    handle_GET_launchPrep,
    handle_GET_locations,
    handle_GET_math_pca,
    handle_GET_math_pca2,
    handle_GET_metadata,
    handle_GET_metadata_answers,
    handle_GET_metadata_choices,
    handle_GET_metadata_questions,
    handle_GET_nextComment,
    handle_GET_notifications_subscribe,
    handle_GET_notifications_unsubscribe,
    handle_GET_participants,
    handle_GET_participation,
    handle_GET_participationInit,
    handle_GET_perfStats,
    handle_GET_ptptois,
    handle_GET_reports,
    handle_GET_snapshot,
    handle_GET_testConnection,
    handle_GET_testDatabase,
    handle_GET_tryCookie,
    handle_GET_twitter_image,
    handle_GET_twitter_oauth_callback,
    handle_GET_twitter_users,
    handle_GET_twitterBtn,
    handle_GET_users,
    handle_GET_verification,
    handle_GET_votes,
    handle_GET_votes_famous,
    handle_GET_votes_me,
    handle_GET_xids,
    handle_GET_zinvites,
    handle_POST_auth_deregister,
    handle_POST_auth_facebook,
    handle_POST_auth_login,
    handle_POST_auth_new,
    handle_POST_auth_password,
    handle_POST_auth_pwresettoken,
    handle_POST_comments,
    handle_POST_contexts,
    handle_POST_contributors,
    handle_POST_conversation_close,
    handle_POST_conversation_reopen,
    handle_POST_conversations,
    handle_POST_convSubscriptions,
    handle_POST_domainWhitelist,
    handle_POST_einvites,
    handle_POST_joinWithInvite,
    handle_POST_math_update,
    handle_POST_metadata_answers,
    handle_POST_metadata_questions,
    handle_POST_metrics,
    handle_POST_notifyTeam,
    handle_POST_participants,
    handle_POST_ptptCommentMod,
    handle_POST_query_participants_by_metadata,
    handle_POST_reportCommentSelections,
    handle_POST_reports,
    handle_POST_reserve_conversation_id,
    handle_POST_sendCreatedLinkToEmail,
    handle_POST_sendEmailExportReady,
    handle_POST_stars,
    handle_POST_trashes,
    handle_POST_tutorial,
    handle_POST_upvotes,
    handle_POST_users_invite,
    handle_POST_votes,
    handle_POST_xidWhitelist,
    handle_POST_zinvites,
    handle_PUT_comments,
    handle_PUT_conversations,
    handle_PUT_participants_extended,
    handle_PUT_ptptois,
    handle_PUT_reports,
    handle_PUT_users
  };
  return returnObject;
}
export { initializePolisHelpers };
export default { initializePolisHelpers };
