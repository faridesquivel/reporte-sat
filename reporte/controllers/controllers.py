# -*- coding: utf-8 -*-
from odoo import http
import logging
import requests


_logger = logging.getLogger(__name__)
class Reporte(http.Controller):
    @http.route('/reporte/reporte/', auth='public')
    def index(self, **kw):
        return "Hello, world"

    @http.route('/reporte/auth/<token>', auth='public', website=True)
    def auth(self, **kw):
        _logger.info(kw.get('token'))
        vals = http.request.env['reporte.auth'].search([])
        _logger.info(vals)
        return http.request.render('reporte.listing', {
            'token': kw.get('token')
        })