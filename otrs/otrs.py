#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from logging.handlers import TimedRotatingFileHandler
from logging import Formatter, getLogger
import os

from cortexutils.responder import Responder

from otrs_python_api.article import Article
from otrs_python_api.exceptions import AuthError, AccessDeniedError, InvalidParameterError, OTRSException
from otrs_python_api.ticket import Ticket
from otrs_python_api.otrs import OTRS
from otrs_python_api.utils.configuration_loading import logger as otrs_python_api_logger
from responder_commons.report_maker import IncidentReportMaker, logger as responder_commons_logger
from responder_commons.mailreporter_client import ReportGeneratorException
from responder_commons.translator import BDError, logger as db_manager_logger

from requests.exceptions import ConnectTimeout, ReadTimeout, Timeout


class Otrs(Responder):
    DEFAULT_MIME_TYPE = "text/html"
    CHARSET = "UTF8"

    def __init__(self):
        Responder.__init__(self)
        self.error_message = "Param {0} in {1} is required"
        self.log_file_path = self.get_param('config.log_file_path', None,
                                            self.error_message.format("log_file_path", "config"))
        self.log_level = self.get_param('config.log_level', None, self.error_message.format("log_level", "config"))
        self.log_rotation_interval = self.get_param('config.log_rotation_interval', None, self.error_message.
                                                    format("log_rotation_interval", "config"))
        self.log_backup_count = self.get_param('config.log_backup_count', None,
                                               self.error_message.format("log_backup_count", "config"))
        self.otrs_url = self.get_param('config.otrs_url', None,
                                       self.error_message.format("otrs_url", "config"))
        self.otrs_login = self.get_param('config.otrs_login', None,
                                         self.error_message.format("otrs_login", "config"))
        self.otrs_password = self.get_param('config.otrs_password', None,
                                            self.error_message.format("otrs_password", "config"))
        self.otrs_interface = self.get_param('config.otrs_interface', None,
                                             self.error_message.format("otrs_interface", "config"))
        self.otrs_verify = self.get_param('config.otrs_verify', None,
                                          self.error_message.format("otrs_verify", "config"))

        otrs_session_timeout = self.get_param('config.otrs_session_timeout')
        self.otrs_session_timeout = float(otrs_session_timeout) if otrs_session_timeout else None
        otrs_connect_timeout = self.get_param('config.otrs_connect_timeout')
        self.otrs_connect_timeout = float(otrs_connect_timeout) if otrs_connect_timeout else None
        otrs_read_timeout = self.get_param('config.otrs_read_timeout')
        self.otrs_read_timeout = float(otrs_read_timeout) if otrs_read_timeout else None
        self.otrs_webservice_url = self.get_param('config.otrs_webservice_url')
        self.otrs_mime_type = self.get_param('config.mime_type') or Otrs.DEFAULT_MIME_TYPE

        self.translate_db_engine = self.get_param('config.translate_db_engine', None,
                                                  self.error_message.format("translate_db_engine", "config"))
        self.translate_db_user = self.get_param('config.translate_db_user', None,
                                                self.error_message.format("translate_db_user", "config"))
        self.translate_db_password = self.get_param('config.translate_db_password', None,
                                                    self.error_message.format("translate_db_password", "config"))
        self.translate_db_host = self.get_param('config.translate_db_host', None,
                                                self.error_message.format("translate_db_host", "config"))
        self.translate_db_port = self.get_param('config.translate_db_port', None,
                                                self.error_message.format("translate_db_port", "config"))
        self.translate_db_name = self.get_param('config.translate_db_name', None,
                                                self.error_message.format("translate_db_name", "config"))
        self.mail_reporter_host = self.get_param('config.mail_reporter_host', None,
                                                 self.error_message.format("mail_reporter_host", "config"))

        self.logger = getLogger(__name__)
        self.prepare_loggers()

    def return_error_message(self, message):
        self.logger.error(message)
        self.error(message)

    def prepare_loggers(self):
        directory = os.path.dirname(self.log_file_path)
        try:
            os.stat(directory)
        except OSError as e:
            self.error(f"Logger directory {directory} errors: {e}")

        file_handler = TimedRotatingFileHandler(filename=self.log_file_path, when=self.log_rotation_interval,
                                                backupCount=self.log_backup_count, encoding='utf-8')
        file_handler.setLevel(level=self.log_level)
        file_handler.setFormatter(Formatter
                                  ('%(asctime)s - %(levelname)-10s - [in %(pathname)s:%(lineno)d]: - %(message)s'))
        self.logger.addHandler(file_handler)
        responder_commons_logger.addHandler(file_handler)
        db_manager_logger.addHandler(file_handler)
        otrs_python_api_logger.addHandler(file_handler)

    def validate_args(self, state_id, priority_id, customer_user, type_id, service_id, queue_id, client_company,
                      language, severity):
        if not isinstance(state_id, int):
            self.return_error_message(f"State_id {state_id} must be int")
        if not isinstance(priority_id, int):
            self.return_error_message(f"Priority_id {priority_id} must be int")
        if not isinstance(customer_user, str):
            self.return_error_message(f"Customer_user {customer_user} must be str")
        if not isinstance(type_id, int):
            self.return_error_message(f"Type_id {type_id} must be int")
        if not isinstance(service_id, int):
            self.return_error_message(f"Service_id {service_id} must be int")
        if not isinstance(queue_id, int):
            self.return_error_message(f"Queue_id {queue_id} must be int")
        if not isinstance(client_company, int):
            self.return_error_message(f"Client_company {client_company} must be int")
        if not isinstance(language, str):
            self.return_error_message(f"Language {language} must be str")
        if not isinstance(severity, int):
            self.return_error_message(f"Severity in data {severity} must be int")

    def run(self):
        message = self.error_message
        incident = self.get_param('data')
        if incident is None:
            self.return_error_message(message.format("incident", "data"))
        if not incident:
            self.return_error_message("Empty incident in data")
        if not isinstance(incident, dict):
            self.return_error_message("Incident {} must be dict".format(incident))

        incident_id = incident.get("id", None)
        if incident_id is None:
            self.return_error_message(message.format("id", "data"))
        if not isinstance(incident_id, str):
            self.return_error_message("Incident id {} must be string".format(incident_id))

        state_id = self.get_param('parameters.state_id')
        if state_id is None:
            self.return_error_message(message.format("state_id", "parameters"))
        priority_id = self.get_param('parameters.priority_id')
        if priority_id is None:
            self.return_error_message(message.format("priority_id", "parameters"))
        customer_user = self.get_param('parameters.customer_user')
        if customer_user is None:
            self.return_error_message(message.format("customer_user", "parameters"))
        type_id = self.get_param('parameters.type_id')
        if type_id is None:
            self.return_error_message(message.format("type_id", "parameters"))
        service_id = self.get_param('parameters.service_id')
        if service_id is None:
            self.return_error_message(message.format("service_id", "parameters"))
        queue_id = self.get_param('parameters.queue_id')
        if queue_id is None:
            self.return_error_message(message.format("queue_id", "parameters"))
        client_company = self.get_param('parameters.client_company')
        if client_company is None:
            self.return_error_message(message.format("client_company", "parameters"))
        language = self.get_param('parameters.language')
        if language is None:
            self.return_error_message(message.format("language", "parameters"))
        severity = self.get_param('data.severity')
        if severity is None:
            self.return_error_message(message.format("severity", "data"))

        self.validate_args(state_id=state_id, priority_id=priority_id, customer_user=customer_user, type_id=type_id,
                           service_id=service_id, queue_id=queue_id, client_company=client_company, language=language,
                           severity=severity)

        incident_report_maker = IncidentReportMaker(dict(
            translator=dict(
                db_engine=self.translate_db_engine,
                db_user=self.translate_db_user,
                db_pass=self.translate_db_password,
                db_host=self.translate_db_host,
                db_port=self.translate_db_port,
                db_name=self.translate_db_name),
            mail_reporter=dict(host=self.mail_reporter_host)
        ))

        try:
            report = incident_report_maker.make_report(
                language_name=language,
                is_mail_alert=False,
                incident=incident,
                b64=False,
                other_translation=dict(
                    service_otrsresponder_subject='siem_incident_detection',
                    service_otrsresponder_title='siem'
                ))
        except ReportGeneratorException as e:
            self.return_error_message(f"Error building report: {e}")
        except BDError as e:
            self.return_error_message(f"Database error while building report {e}")
        except Exception as e:
            self.return_error_message(f"Some error building report: {e}")

        html_incident = report["report"]
        subject = report["other_translation"]["service_otrsresponder_subject"]
        title = report["other_translation"]["service_otrsresponder_title"]

        ticket = Ticket.create(
            Title=title,
            StateID=state_id,
            PriorityID=priority_id,
            CustomerUser=customer_user,
            TypeID=type_id,
            ServiceID=service_id,
            QueueID=queue_id
        )
        ticket.set_dynamic_field('ClientCompany', client_company)
        ticket.set_dynamic_field('IncidentRootId', incident_id)

        article = Article(Subject=subject,
                          Body=html_incident,
                          MimeType=self.otrs_mime_type,
                          Charset=Otrs.CHARSET)
        connector = OTRS(
            url=self.otrs_url,
            login=self.otrs_login,
            password=self.otrs_password,
            interface=self.otrs_interface,
            verify=self.otrs_verify,
            session_timeout=self.otrs_session_timeout,
            webservice_url=self.otrs_webservice_url,
            connect_timeout=self.otrs_connect_timeout,
            read_timeout=self.otrs_read_timeout
        )
        try:
            connector.ticket_create(ticket, article)
        except AuthError as e:
            self.return_error_message(f"Authentication error: {e}")
        except AccessDeniedError as e:
            self.return_error_message(f"Access denied error: {e}")
        except InvalidParameterError as e:
            self.return_error_message(f"Invalid parameter error: {e}")
        except OTRSException as e:
            self.return_error_message(f"OTRS exception: {e}")
        except (ConnectTimeout, ReadTimeout, Timeout) as e:
            self.return_error_message(f"Timeout error: {e}")

        self.report({'message': 'ticket created'})

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='ticket created')]


if __name__ == '__main__':
    Otrs().run()
