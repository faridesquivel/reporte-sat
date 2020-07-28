# -*- coding: utf-8 -*-
from odoo import models, fields, api
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from OpenSSL import crypto
from lxml import etree
import werkzeug
import logging
import os
import functools
import base64
import xmlrpc.client
import hashlib
import base64
import uuid
import requests

_logger = logging.getLogger(__name__)
class Auth(models.Model):
    
    _name = 'reporte.auth'
    _description = 'Reporte de facturas SAT'
    
    uid = fields.Char()
    privateKey = fields.Binary(attachment=False)
    cert = fields.Binary(attachment=False)
    privateKeyPass = fields.Char(string='Password')
    token = fields.Char()

    def do_login(self):
        context = self._context
        current_uid = context.get('uid')
        
        FIEL_KEY = os.path.expanduser('./src/user/reporte/models/privateKey.key')
        FIEL_CER = os.path.expanduser('./src/user/reporte/models/cert.cer')
        FIEL_PAS = os.path.expanduser('./src/user/reporte/models/pass.txt')
        
        inputx = BytesIO()
        inputx.write(base64.b64decode(self.privateKey))
        inputy = BytesIO()
        inputy.write(base64.b64decode(self.cert))
        
        p_con = inputx.getvalue()
        c_con = inputy.getvalue()
        fiel = Fiel(c_con, p_con, self.privateKeyPass)

        auth = Autenticacion(fiel)

        token = auth.obtener_token()

        _logger.info(token)
        
        vals = {
            'uid': current_uid,
            'cert': c_con,
            'privateKey': p_con,
            'privateKeyPass': self.privateKeyPass,
            'token': token
        }
        self.env['reporte.auth'].create(vals)
        
        return {
            'name': 'Datos para reporte',
            'view_mode': 'form',
            'res_model': 'reporte.data',
            'view_id': False,
            'type': 'ir.actions.act_window',
            'context': { 'token': token, 'fiel': fiel } 
        }

class List(models.Model):
    _name = "list.reportes"
    _description = "Listado de facturas SAT"
    
    rfcEmisor = fields.Char(string='RFC Emisor')
    rfcReceptor = fields.Char(string='RFC Receptor')
    
    def get_xmls(self):
        return True

class DataEntry(models.Model):
    _name = "reporte.data"
    _description = "Datos para descarga de facturas SAT"
    
    rfcSolicitante = fields.Char(string='RFC Solicitante')
    startDate = fields.Date(string='Fecha inicio')
    endDate = fields.Date(string='Fecha final')
    rfcEmisor = fields.Char(string='RFC Emisor')
    rfcReceptor = fields.Char(string='RFC Receptor')
    
    def start_download(self):
        vals = self.env['reporte.auth'].search([])
        _logger.info(vals[0].token)
        fiel = Fiel(vals[0].cert, vals[0].privateKey, vals[0].privateKeyPass)

        descarga = SolicitaDescarga(fiel)

        token = vals[0].token
        rfc_solicitante = self.rfcSolicitante
        fecha_inicial = datetime.datetime(2018, 1, 1)
        fecha_final = datetime.datetime(2018, 12, 31)
        rfc_emisor = self.rfcEmisor
        rfc_receptor = self.rfcReceptor
        # Emitidos
        result = descarga.solicitar_descarga(token, rfc_solicitante, fecha_inicial, fecha_final, rfc_emisor=rfc_emisor)

        _logger.info(result)
        return True

class Autenticacion():
    SOAP_URL = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc'
    SOAP_ACTION = 'http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica'
    NSMAP = {
        's': 'http://schemas.xmlsoap.org/soap/envelope/',
        'u': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
    }
    S_NSMAP = {
        'o': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    }

    def __init__(self, fiel):
        self.fiel = fiel
    
    def __generar_soapreq__(self, id):
        date_created = datetime.utcnow()
        date_expires = date_created + timedelta(seconds=300)
        date_created = date_created.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        date_expires = date_expires.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        soap_req = etree.Element('{{{}}}{}'.format(self.NSMAP['s'], 'Envelope'), nsmap=self.NSMAP)
        
        header = etree.SubElement(soap_req, '{{{}}}{}'.format(self.NSMAP['s'], 'Header'))
        
        security = etree.SubElement(header, '{{{}}}{}'.format(self.S_NSMAP['o'], 'Security'), nsmap=self.S_NSMAP)
        security.set('{{{}}}{}'.format(self.NSMAP['s'], 'mustUnderstand'), '1')

        timestamp = etree.SubElement(security, '{{{}}}{}'.format(self.NSMAP['u'], 'Timestamp'))
        timestamp.set('{{{}}}{}'.format(self.NSMAP['u'], 'Id'), '_0')
        
        created = etree.SubElement(timestamp, '{{{}}}{}'.format(self.NSMAP['u'], 'Created'))
        created.text = date_created
        
        expires = etree.SubElement(timestamp, '{{{}}}{}'.format(self.NSMAP['u'], 'Expires'))
        expires.text = date_expires
        
        binarysecuritytoken = etree.SubElement(security, '{{{}}}{}'.format(self.S_NSMAP['o'], 'BinarySecurityToken'))
        binarysecuritytoken.set('{{{}}}{}'.format(self.NSMAP['u'], 'Id'), str(id))
        binarysecuritytoken.set('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3')
        binarysecuritytoken.set('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary')

        signature = etree.SubElement(security, 'Signature', nsmap={None: 'http://www.w3.org/2000/09/xmldsig#'})

        signedinfo = etree.SubElement(signature, 'SignedInfo', nsmap={None: 'http://www.w3.org/2000/09/xmldsig#'})

        canonicalizationmethod = etree.SubElement(signedinfo, 'CanonicalizationMethod')
        canonicalizationmethod.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')

        signaturemethod = etree.SubElement(signedinfo, 'SignatureMethod')
        signaturemethod.set('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')

        reference = etree.SubElement(signedinfo, 'Reference')
        reference.set('URI', '#_0')

        transforms = etree.SubElement(reference, 'Transforms')

        transform = etree.SubElement(transforms, 'Transform')
        transform.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')

        digestmethod = etree.SubElement(reference, 'DigestMethod')
        digestmethod.set('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1')

        digestvalue = etree.SubElement(reference, 'DigestValue')

        signaturevalue = etree.SubElement(signature, 'SignatureValue')

        keyinfo = etree.SubElement(signature, 'KeyInfo')

        securitytokenreference = etree.SubElement(keyinfo, '{{{}}}{}'.format(self.S_NSMAP['o'], 'SecurityTokenReference'))

        reference = etree.SubElement(securitytokenreference, '{{{}}}{}'.format(self.S_NSMAP['o'], 'Reference'))
        reference.set('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3')
        reference.set('URI', '#{}'.format(id))

        body = etree.SubElement(soap_req, '{{{}}}{}'.format(self.NSMAP['s'], 'Body'))

        etree.SubElement(body, 'Autentica', nsmap={None: 'http://DescargaMasivaTerceros.gob.mx'})

        to_digest = etree.tostring(timestamp, method='c14n', exclusive=1)

        digest = base64.b64encode(hashlib.new('sha1', to_digest).digest())
        
        digestvalue.text = digest

        to_sign = etree.tostring(signedinfo, method='c14n', exclusive=1)

        firma = self.fiel.firmar_sha1(to_sign)

        signaturevalue.text = firma

        binarysecuritytoken.text = self.fiel.cer_to_base64()

        return etree.tostring(soap_req)

    def obtener_token(self, id=uuid.uuid4()):
        
        soapreq = self.__generar_soapreq__(id)

        headers = {
            'Content-type': 'text/xml;charset="utf-8"',
            'Accept': 'text/xml',
            'Cache-Control': 'no-cache',
            'SOAPAction': self.SOAP_ACTION
        }

        response = requests.post(self.SOAP_URL, data=soapreq, headers=headers, verify=True)

        if response.status_code != requests.codes['ok']:
            if not response.text.startswith('<s:Envelope'):
                ex = 'El webservice Autenticacion responde: {}'.format(response.text)
            else:
                resp_xml = etree.fromstring(response.text)
                ex = resp_xml.find('s:Body/s:Fault/faultstring', namespaces=self.NSMAP).text
            raise Exception(ex)

        if not response.text.startswith('<s:Envelope'):
            ex = 'El webservice Autenticacion responde: {}'.format(response.text)
            raise Exception(ex)

        nsmap= {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            None: 'http://DescargaMasivaTerceros.gob.mx'
        }

        resp_xml = etree.fromstring(response.text)

        token = resp_xml.find('s:Body/AutenticaResponse/AutenticaResult', namespaces=nsmap)

        return token.text
    
class Fiel():
    def __init__(self, cer_der, key_der, passphrase):
        self.__importar_cer__(cer_der)
        self.__importar_key__(key_der, passphrase)

    def __importar_cer__(self, cer_der):
        # Cargar certificado en formato DER
        self.cer = crypto.load_certificate(crypto.FILETYPE_ASN1, cer_der)

    def __importar_key__(self, key_der, passphrase):
        # Importar KEY en formato DER
        self.key = RSA.importKey(key_der, passphrase)
        # Crear objeto para firmar
        self.signer = PKCS1_v1_5.new(self.key)

    def firmar_sha1(self, texto):
        # Generar SHA1
        sha1 = SHA.new(texto)
        # Firmar
        firma = self.signer.sign(sha1)
        # Pasar a base64
        b64_firma = base64.b64encode(firma)
        return b64_firma

    def cer_to_base64(self):
        # Extraer DER de certificado
        cer = crypto.dump_certificate(crypto.FILETYPE_ASN1, self.cer)
        # Pasar a b64
        return base64.b64encode(cer)

    def cer_issuer(self):
        # Extraer issuer
        d = self.cer.get_issuer().get_components()
        # Generar cafena issuer
        datos = ''
        for t in d:
            datos += '{}={},'.format(t[0], t[1])

        datos = datos[:-1]
        try:
            return datos.decode('utf8')
        except AttributeError:
            return datos

    def cer_serial_number(self):
        # Obtener numero de serie del certificado
        serial = self.cer.get_serial_number()
        # Pasar numero de serie a string
        return str(serial)
    
class DescargaMasiva():
    SOAP_URL = 'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc'
    SOAP_ACTION = 'http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar'
    NSMAP = {
        's': 'http://schemas.xmlsoap.org/soap/envelope/',
        'des': 'http://DescargaMasivaTerceros.sat.gob.mx',
        'xd': 'http://www.w3.org/2000/09/xmldsig#'
    }    
    
    def __init__(self, fiel):
        self.fiel = fiel

    def __generar_soapreq__(self, rfc_solicitante, id_paquete):
        soap_req = etree.Element('{{{}}}{}'.format(self.NSMAP['s'], 'Envelope'), nsmap=self.NSMAP)
        
        etree.SubElement(soap_req, '{{{}}}{}'.format(self.NSMAP['s'], 'Header'))

        body = etree.SubElement(soap_req, '{{{}}}{}'.format(self.NSMAP['s'], 'Body'))

        peticiondescarga = etree.SubElement(body, '{{{}}}{}'.format(self.NSMAP['des'], 'PeticionDescargaMasivaTercerosEntrada'))

        peticion_descarga = etree.SubElement(peticiondescarga, '{{{}}}{}'.format(self.NSMAP['des'], 'peticionDescarga'))
        peticion_descarga.set('IdPaquete', id_paquete)
        peticion_descarga.set('RfcSolicitante', rfc_solicitante)
        
        signature = etree.SubElement(peticion_descarga, 'Signature', nsmap={None: 'http://www.w3.org/2000/09/xmldsig#'})

        signedinfo = etree.SubElement(signature, 'SignedInfo', nsmap={None: 'http://www.w3.org/2000/09/xmldsig#'})

        canonicalizationmethod = etree.SubElement(signedinfo, 'CanonicalizationMethod')
        canonicalizationmethod.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')

        signaturemethod = etree.SubElement(signedinfo, 'SignatureMethod')
        signaturemethod.set('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')

        reference = etree.SubElement(signedinfo, 'Reference')
        reference.set('URI', '#_0')

        transforms = etree.SubElement(reference, 'Transforms')

        transform = etree.SubElement(transforms, 'Transform')
        transform.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')

        digestmethod = etree.SubElement(reference, 'DigestMethod')
        digestmethod.set('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1')

        digestvalue = etree.SubElement(reference, 'DigestValue')

        signaturevalue = etree.SubElement(signature, 'SignatureValue')

        keyinfo = etree.SubElement(signature, 'KeyInfo')
        
        x509data = etree.SubElement(keyinfo, 'X509Data')

        x509issuerserial = etree.SubElement(x509data, 'X509IssuerSerial')

        x509issuername = etree.SubElement(x509issuerserial, 'X509IssuerName')
        
        x509serialnumber = etree.SubElement(x509issuerserial, 'X509SerialNumber')
        
        x509certificate = etree.SubElement(x509data, 'X509Certificate')

        to_digest = etree.tostring(peticiondescarga, method='c14n', exclusive=1)

        digest = base64.b64encode(hashlib.new('sha1', to_digest).digest())
        
        digestvalue.text = digest

        to_sign = etree.tostring(signedinfo, method='c14n', exclusive=1)
        
        firma = self.fiel.firmar_sha1(to_sign)

        signaturevalue.text = firma

        x509certificate.text = self.fiel.cer_to_base64()

        x509issuername.text = self.fiel.cer_issuer()

        x509serialnumber.text = self.fiel.cer_serial_number()
        
        return etree.tostring(soap_req)
    
    def descargar_paquete(self, token, rfc_solicitante, id_paquete):
        
        soapreq = self.__generar_soapreq__(rfc_solicitante, id_paquete)

        headers = {
            'Content-type': 'text/xml;charset="utf-8"',
            'Accept': 'text/xml',
            'Cache-Control': 'no-cache',
            'SOAPAction': self.SOAP_ACTION,
            'Authorization': 'WRAP access_token="{}"'.format(token)
        }

        response = requests.post(self.SOAP_URL, data=soapreq, headers=headers, verify=True)

        if response.status_code != requests.codes['ok']:
            if not response.text.startswith('<s:Envelope'):
                ex = 'El webservice Autenticacion responde: {}'.format(response.text)
            else:
                resp_xml = etree.fromstring(response.text)
                ex = resp_xml.find('s:Body/s:Fault/faultstring', namespaces=self.NSMAP).text
            raise Exception(ex)

        if not response.text.startswith('<s:Envelope'):
            ex = 'El webservice Autenticacion responde: {}'.format(response.text)
            raise Exception(ex)
        
        nsmap= {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'h': 'http://DescargaMasivaTerceros.sat.gob.mx',
            None: 'http://DescargaMasivaTerceros.sat.gob.mx'
        }

        resp_xml = etree.fromstring(response.text, parser=etree.XMLParser(huge_tree=True))

        respuesta = resp_xml.find('s:Header/h:respuesta', namespaces=nsmap)

        paquete = resp_xml.find('s:Body/RespuestaDescargaMasivaTercerosSalida/Paquete', namespaces=nsmap)

        ret_val = {
            'cod_estatus': respuesta.get('CodEstatus'),
            'mensaje': respuesta.get('Mensaje'),
            'paquete_b64': paquete.text,
        }

        return ret_val

class SolicitaDescarga():
    SOAP_URL = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc'
    SOAP_ACTION = 'http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga'
    NSMAP = {
        's': 'http://schemas.xmlsoap.org/soap/envelope/',
        'des': 'http://DescargaMasivaTerceros.sat.gob.mx',
        'xd': 'http://www.w3.org/2000/09/xmldsig#'
    }

    def __init__(self, fiel):
        self.fiel = fiel
    
    def __generar_soapreq__(self, rfc_solicitante, fecha_inicial, fecha_final, rfc_emisor, rfc_receptor, tipo_solicitud):
        soap_req = etree.Element('{{{}}}{}'.format(self.NSMAP['s'], 'Envelope'), nsmap=self.NSMAP)
        
        etree.SubElement(soap_req, '{{{}}}{}'.format(self.NSMAP['s'], 'Header'))

        body = etree.SubElement(soap_req, '{{{}}}{}'.format(self.NSMAP['s'], 'Body'))

        solicitadescarga = etree.SubElement(body, '{{{}}}{}'.format(self.NSMAP['des'], 'SolicitaDescarga'))

        solicitud = etree.SubElement(solicitadescarga, '{{{}}}{}'.format(self.NSMAP['des'], 'solicitud'))
        solicitud.set('RfcSolicitante', rfc_solicitante)
        solicitud.set('FechaFinal', fecha_final.strftime('%Y-%m-%dT%H:%M:%S'))
        solicitud.set('FechaInicial', fecha_inicial.strftime('%Y-%m-%dT%H:%M:%S'))
        solicitud.set('TipoSolicitud', tipo_solicitud)
        if rfc_emisor is not None:
            solicitud.set('RfcEmisor', rfc_emisor)
        
        if rfc_receptor is not None:
            solicitud.set('RfcReceptor', rfc_receptor)
        
        signature = etree.SubElement(solicitud, 'Signature', nsmap={None: 'http://www.w3.org/2000/09/xmldsig#'})

        signedinfo = etree.SubElement(signature, 'SignedInfo', nsmap={None: 'http://www.w3.org/2000/09/xmldsig#'})

        canonicalizationmethod = etree.SubElement(signedinfo, 'CanonicalizationMethod')
        canonicalizationmethod.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')

        signaturemethod = etree.SubElement(signedinfo, 'SignatureMethod')
        signaturemethod.set('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')

        reference = etree.SubElement(signedinfo, 'Reference')
        reference.set('URI', '#_0')

        transforms = etree.SubElement(reference, 'Transforms')

        transform = etree.SubElement(transforms, 'Transform')
        transform.set('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#')

        digestmethod = etree.SubElement(reference, 'DigestMethod')
        digestmethod.set('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1')

        digestvalue = etree.SubElement(reference, 'DigestValue')

        signaturevalue = etree.SubElement(signature, 'SignatureValue')

        keyinfo = etree.SubElement(signature, 'KeyInfo')
        
        x509data = etree.SubElement(keyinfo, 'X509Data')

        x509issuerserial = etree.SubElement(x509data, 'X509IssuerSerial')

        x509issuername = etree.SubElement(x509issuerserial, 'X509IssuerName')
        
        x509serialnumber = etree.SubElement(x509issuerserial, 'X509SerialNumber')
        
        x509certificate = etree.SubElement(x509data, 'X509Certificate')

        to_digest = etree.tostring(solicitadescarga, method='c14n', exclusive=1)

        digest = base64.b64encode(hashlib.new('sha1', to_digest).digest())
        
        digestvalue.text = digest

        to_sign = etree.tostring(signedinfo, method='c14n', exclusive=1)

        firma = self.fiel.firmar_sha1(to_sign)

        signaturevalue.text = firma

        x509certificate.text = self.fiel.cer_to_base64()

        x509issuername.text = self.fiel.cer_issuer()

        x509serialnumber.text = self.fiel.cer_serial_number()
        
        return etree.tostring(soap_req)
    
    def solicitar_descarga(
            self, token, rfc_solicitante, fecha_inicial, fecha_final,
            rfc_emisor=None, rfc_receptor=None, tipo_solicitud='CFDI'
        ):
        
        soapreq = self.__generar_soapreq__(
            rfc_solicitante, fecha_inicial, fecha_final, rfc_emisor, rfc_receptor, tipo_solicitud
        )

        headers = {
            'Content-type': 'text/xml;charset="utf-8"',
            'Accept': 'text/xml',
            'Cache-Control': 'no-cache',
            'SOAPAction': self.SOAP_ACTION,
            'Authorization': 'WRAP access_token="{}"'.format(token)
        }

        response = requests.post(self.SOAP_URL, data=soapreq, headers=headers, verify=True)

        if response.status_code != requests.codes['ok']:
            if not response.text.startswith('<s:Envelope'):
                ex = 'El webservice Autenticacion responde: {}'.format(response.text)
            else:
                resp_xml = etree.fromstring(response.text)
                ex = resp_xml.find('s:Body/s:Fault/faultstring', namespaces=self.NSMAP).text
            raise Exception(ex)

        if not response.text.startswith('<s:Envelope'):
            ex = 'El webservice Autenticacion responde: {}'.format(response.text)
            raise Exception(ex)

        nsmap= {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            None: 'http://DescargaMasivaTerceros.sat.gob.mx'
        }

        resp_xml = etree.fromstring(response.text)

        f_val = 's:Body/SolicitaDescargaResponse/SolicitaDescargaResult'

        s_d_r = resp_xml.find(f_val, namespaces=nsmap)

        ret_val = {
            'id_solicitud': s_d_r.get('IdSolicitud'),
            'cod_estatus': s_d_r.get('CodEstatus'),
            'mensaje': s_d_r.get('Mensaje')
        }

        return ret_val