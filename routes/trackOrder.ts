/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response } from 'express'

const challenges = require('../data/datacache').challenges
const db = require('../data/mongodb')

module.exports = function trackOrder () {
  return (req: Request, res: Response) => {
    const tmp_id = utils.disableOnContainerEnv() ? String(req.params.id).replace(/[^\w-]+/g, '') : req.params.id
    var id = null;
    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    if (tmp_id.split('').every(char => char >= '0' && char <= '9')) {
        id = tmp_id
    }
    db.orders.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
