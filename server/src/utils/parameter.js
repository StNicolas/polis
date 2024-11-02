import LruCache from 'lru-cache';
import _ from 'underscore';
import { isUri } from 'valid-url';
import Conversation from '../conversation.js';
import pg from '../db/pg-query.js';
import User from '../user.js';
import fail from './fail.js';
import logger from './logger.js';
import { MPromise } from './metered.js';
function moveToBody(req, _res, next) {
  if (req.query) {
    req.body = req.body || {};
    Object.assign(req.body, req.query);
  }
  if (req.params) {
    req.body = req.body || {};
    Object.assign(req.body, req.params);
  }
  req.p = req.p || {};
  next();
}
function need(name, parserWhichReturnsPromise, assigner) {
  return buildCallback({
    name: name,
    extractor: extractFromBody,
    parserWhichReturnsPromise: parserWhichReturnsPromise,
    assigner: assigner,
    required: true
  });
}
function want(name, parserWhichReturnsPromise, assigner, defaultVal) {
  return buildCallback({
    name: name,
    extractor: extractFromBody,
    parserWhichReturnsPromise: parserWhichReturnsPromise,
    assigner: assigner,
    required: false,
    defaultVal: defaultVal
  });
}
function needCookie(name, parserWhichReturnsPromise, assigner) {
  return buildCallback({
    name: name,
    extractor: extractFromCookie,
    parserWhichReturnsPromise: parserWhichReturnsPromise,
    assigner: assigner,
    required: true
  });
}
function wantCookie(name, parserWhichReturnsPromise, assigner, defaultVal) {
  return buildCallback({
    name: name,
    extractor: extractFromCookie,
    parserWhichReturnsPromise: parserWhichReturnsPromise,
    assigner: assigner,
    required: false,
    defaultVal: defaultVal
  });
}
function needHeader(name, parserWhichReturnsPromise, assigner, defaultVal) {
  return buildCallback({
    name: name,
    extractor: extractFromHeader,
    parserWhichReturnsPromise: parserWhichReturnsPromise,
    assigner: assigner,
    required: true,
    defaultVal: defaultVal
  });
}
function wantHeader(name, parserWhichReturnsPromise, assigner, defaultVal) {
  return buildCallback({
    name: name,
    extractor: extractFromHeader,
    parserWhichReturnsPromise: parserWhichReturnsPromise,
    assigner: assigner,
    required: false,
    defaultVal: defaultVal
  });
}
function extractFromBody(req, name) {
  if (!req.body) {
    return void 0;
  }
  return req.body[name];
}
function extractFromCookie(req, name) {
  if (!req.cookies) {
    return void 0;
  }
  return req.cookies[name];
}
function extractFromHeader(req, name) {
  if (!req.headers) {
    return void 0;
  }
  return req.headers[name.toLowerCase()];
}
function buildCallback(config) {
  const name = config.name;
  const parserWhichReturnsPromise = config.parserWhichReturnsPromise;
  const assigner = config.assigner;
  const required = config.required;
  const defaultVal = config.defaultVal;
  const extractor = config.extractor;
  if (typeof assigner !== 'function') {
    throw new Error('bad arg for assigner');
  }
  if (typeof parserWhichReturnsPromise !== 'function') {
    throw new Error('bad arg for parserWhichReturnsPromise');
  }
  return (req, res, next) => {
    const val = extractor(req, name);
    if (!_.isUndefined(val) && !_.isNull(val)) {
      parserWhichReturnsPromise(val)
        .then(
          (parsed) => {
            assigner(req, name, parsed);
            next();
          },
          (err) => {
            const s = `polis_err_param_parse_failed_${name} (val='${val}', error=${err})`;
            logger.error(s, err);
            res.status(400);
            next(s);
            return;
          }
        )
        .catch((err) => {
          fail(res, 400, 'polis_err_misc', err);
          return;
        });
    } else if (!required) {
      if (typeof defaultVal !== 'undefined') {
        assigner(req, name, defaultVal);
      }
      next();
    } else {
      const s = `polis_err_param_missing_${name}`;
      logger.error(s);
      res.status(400);
      next(s);
    }
  };
}
function isEmail(s) {
  return typeof s === 'string' && s.length < 999 && s.indexOf('@') > 0;
}
function getEmail(s) {
  return new Promise((resolve, reject) => {
    if (!isEmail(s)) {
      return reject('polis_fail_parse_email');
    }
    resolve(s);
  });
}
function getPassword(s) {
  return new Promise((resolve, reject) => {
    if (typeof s !== 'string' || s.length > 999 || s.length === 0) {
      return reject('polis_fail_parse_password');
    }
    resolve(s);
  });
}
function getPasswordWithCreatePasswordRules(s) {
  return getPassword(s).then((s) => {
    if (typeof s !== 'string' || s.length < 6) {
      throw new Error('polis_err_password_too_short');
    }
    return s;
  });
}
function getOptionalStringLimitLength(limit) {
  return (s) =>
    new Promise((resolve, reject) => {
      if (s.length && s.length > limit) {
        return reject('polis_fail_parse_string_too_long');
      }
      s = s.replace(/^ */, '').replace(/ *$/, '');
      resolve(s);
    });
}
function getStringLimitLength(min, max) {
  if (_.isUndefined(max)) {
    max = min;
    min = 1;
  }
  return (s) =>
    new Promise((resolve, reject) => {
      if (typeof s !== 'string') {
        return reject('polis_fail_parse_string_missing');
      }
      if (s.length && s.length > max) {
        return reject('polis_fail_parse_string_too_long');
      }
      if (s.length && s.length < min) {
        return reject('polis_fail_parse_string_too_short');
      }
      s = s.replace(/^ */, '').replace(/ *$/, '');
      resolve(s);
    });
}
function getUrlLimitLength(limit) {
  return (s) => {
    getStringLimitLength(limit)(s).then(
      (s) =>
        new Promise((resolve, reject) => {
          if (isUri(s)) {
            return resolve(s);
          }
          return reject('polis_fail_parse_url_invalid');
        })
    );
  };
}
function getInt(s) {
  return new Promise((resolve, reject) => {
    if (_.isNumber(s) && s >> 0 === s) {
      return resolve(s);
    }
    const x = Number.parseInt(s);
    if (Number.isNaN(x)) {
      return reject(`polis_fail_parse_int ${s}`);
    }
    resolve(x);
  });
}
function getBool(s) {
  return new Promise((resolve, reject) => {
    const type = typeof s;
    if ('boolean' === type) {
      return resolve(s);
    }
    if ('number' === type) {
      if (s === 0) {
        return resolve(false);
      }
      return resolve(true);
    }
    s = s.toLowerCase();
    if (s === 't' || s === 'true' || s === 'on' || s === '1') {
      return resolve(true);
    }
    if (s === 'f' || s === 'false' || s === 'off' || s === '0') {
      return resolve(false);
    }
    reject('polis_fail_parse_boolean');
  });
}
function getIntInRange(min, max) {
  return (s) =>
    getInt(s).then((x) => {
      if (x < min || max < x) {
        throw new Error('polis_fail_parse_int_out_of_range');
      }
      return x;
    });
}
const reportIdToRidCache = new LruCache({
  max: 1000
});
const getZidFromConversationId = Conversation.getZidFromConversationId;
function getRidFromReportId(report_id) {
  return new MPromise('getRidFromReportId', (resolve, reject) => {
    const cachedRid = reportIdToRidCache.get(report_id);
    if (cachedRid) {
      resolve(cachedRid);
      return;
    }
    pg.query_readOnly('select rid from reports where report_id = ($1);', [report_id], (err, results) => {
      logger.error(`polis_err_fetching_rid_for_report_id ${report_id}`, err);
      if (err) {
        return reject(err);
      }
      if (!results || !results.rows || !results.rows.length) {
        return reject('polis_err_fetching_rid_for_report_id');
      }
      const rid = results.rows[0].rid;
      reportIdToRidCache.set(report_id, rid);
      return resolve(rid);
    });
  });
}
const parseConversationId = getStringLimitLength(1, 100);
function getConversationIdFetchZid(s) {
  return parseConversationId(s).then((conversation_id) =>
    getZidFromConversationId(conversation_id).then((zid) => Number(zid))
  );
}
const parseReportId = getStringLimitLength(1, 100);
function getReportIdFetchRid(s) {
  return parseReportId(s).then((report_id) => getRidFromReportId(report_id).then((rid) => Number(rid)));
}
function getNumber(s) {
  return new Promise((resolve, reject) => {
    if (_.isNumber(s)) {
      return resolve(s);
    }
    const x = Number.parseFloat(s);
    if (Number.isNaN(x)) {
      return reject('polis_fail_parse_number');
    }
    resolve(x);
  });
}
function getNumberInRange(min, max) {
  return (s) =>
    getNumber(s).then((x) => {
      if (x < min || max < x) {
        throw new Error('polis_fail_parse_number_out_of_range');
      }
      return x;
    });
}
function getArrayOfString(a, _maxStrings, _maxLength) {
  return new Promise((resolve, reject) => {
    let result;
    if (_.isString(a)) {
      result = a.split(',');
    }
    if (!_.isArray(result)) {
      return reject('polis_fail_parse_int_array');
    }
    resolve(result);
  });
}
function getArrayOfStringNonEmpty(a, _maxStrings, _maxLength) {
  if (!a || !a.length) {
    return Promise.reject('polis_fail_parse_string_array_empty');
  }
  return getArrayOfString(a);
}
function getArrayOfStringLimitLength(maxStrings, maxLength) {
  return (a) => getArrayOfString(a, maxStrings || 999999999, maxLength);
}
function getArrayOfStringNonEmptyLimitLength(maxStrings, maxLength) {
  return (a) => getArrayOfStringNonEmpty(a, maxStrings || 999999999, maxLength);
}
function getArrayOfInt(a) {
  if (_.isString(a)) {
    a = a.split(',');
  }
  if (!_.isArray(a)) {
    return Promise.reject('polis_fail_parse_int_array');
  }
  function integer(i) {
    return Number(i) >> 0;
  }
  return Promise.resolve(a.map(integer));
}
function assignToP(req, name, x) {
  req.p = req.p || {};
  if (!_.isUndefined(req.p[name])) {
    logger.error(`polis_err_clobbering ${name}`);
  }
  req.p[name] = x;
}
function assignToPCustom(name) {
  return (req, _ignoredName, x) => {
    assignToP(req, name, x);
  };
}
function resolve_pidThing(pidThingStringName, assigner, loggingString) {
  if (_.isUndefined(loggingString)) {
    loggingString = '';
  }
  logger.debug(`resolve_pidThing ${loggingString}`);
  return (req, res, next) => {
    if (!req.p) {
      fail(res, 500, 'polis_err_this_middleware_should_be_after_auth_and_zid');
      next('polis_err_this_middleware_should_be_after_auth_and_zid');
    }
    const existingValue = extractFromBody(req, pidThingStringName) || extractFromCookie(req, pidThingStringName);
    if (existingValue === 'mypid' && req?.p?.zid && req.p.uid) {
      User.getPidPromise(req.p.zid, req.p.uid)
        .then((pid) => {
          if (pid >= 0) {
            assigner(req, pidThingStringName, pid);
          }
          next();
        })
        .catch((err) => {
          fail(res, 500, 'polis_err_mypid_resolve_error', err);
          next(err);
        });
    } else if (existingValue === 'mypid') {
      next();
    } else if (!_.isUndefined(existingValue)) {
      getInt(existingValue)
        .then((pidNumber) => {
          assigner(req, pidThingStringName, pidNumber);
          next();
        })
        .catch((err) => {
          fail(res, 500, 'polis_err_pid_error', err);
          next(err);
        });
    } else {
      next();
    }
  };
}
export {
  assignToP,
  assignToPCustom,
  getArrayOfInt,
  getArrayOfStringNonEmpty,
  getArrayOfStringNonEmptyLimitLength,
  getBool,
  getConversationIdFetchZid,
  getEmail,
  getInt,
  getIntInRange,
  getNumberInRange,
  getOptionalStringLimitLength,
  getPassword,
  getPasswordWithCreatePasswordRules,
  getReportIdFetchRid,
  getStringLimitLength,
  getUrlLimitLength,
  moveToBody,
  need,
  needCookie,
  needHeader,
  resolve_pidThing,
  want,
  wantCookie,
  wantHeader
};
