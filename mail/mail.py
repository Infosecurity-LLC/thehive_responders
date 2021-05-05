#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from logging.handlers import TimedRotatingFileHandler
from logging import Formatter, getLogger
import os

from socutils import mail
from responder_commons.report_maker import IncidentReportMaker, logger as responder_commons_logger
from responder_commons.mailreporter_client import ReportGeneratorException
from responder_commons.translator import BDError, logger as db_manager_logger

# installed inside the cortex
from cortexutils.responder import Responder

mapping_severity_to_images = {
    1: "mail/images/s1.jpg",
    2: "mail/images/s2.jpg",
    3: "mail/images/s3.jpg",
    4: "mail/images/s3.jpg"
}


class Mail(Responder):

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
        self.smtp_server = self.get_param('config.smtp_server', None,
                                          self.error_message.format("smtp_server", "config"))
        self.smtp_port = self.get_param('config.smtp_port', None,
                                        self.error_message.format("smtp_port", "config"))
        self.smtp_ssl = self.get_param('config.smtp_ssl', None,
                                       self.error_message.format("smtp_ssl", "config"))
        self.smtp_username = self.get_param('config.smtp_username')
        self.smtp_password = self.get_param('config.smtp_password')
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
            self.error("Logger directory {0} errors: {1}".format(directory, e))

        file_handler = TimedRotatingFileHandler(filename=self.log_file_path, when=self.log_rotation_interval,
                                                backupCount=self.log_backup_count, encoding='utf-8')
        file_handler.setLevel(level=self.log_level)
        file_handler.setFormatter(Formatter
                                  ('%(asctime)s - %(levelname)-10s - [in %(pathname)s:%(lineno)d]: - %(message)s'))
        self.logger.addHandler(file_handler)
        responder_commons_logger.addHandler(file_handler)
        db_manager_logger.addHandler(file_handler)

    def validate_args(self, language, sender, recipients, severity):
        if not isinstance(language, str):
            self.return_error_message("Language {} must be str".format(language))
        if not isinstance(sender, str):
            self.return_error_message("Sender {} must be str".format(sender))
        if not isinstance(recipients, list):
            self.return_error_message("Recipients {} must be list".format(recipients))
        if not all([isinstance(recipient, str) for recipient in recipients]):
            self.return_error_message("Recipient elements {} must be str".format(recipients))
        if not isinstance(severity, int):
            self.return_error_message("Severity in data {} must be int".format(severity))

    def run(self):
        message = self.error_message
        incident = self.get_param('data')
        if incident is None:
            self.return_error_message(message.format("incident", "data"))
        if not incident:
            self.return_error_message("Empty incident in data")
        if not isinstance(incident, dict):
            self.return_error_message("Incident {} must be dict".format(incident))

        language = self.get_param('parameters.language')
        if language is None:
            self.return_error_message(message.format("language", "parameters"))
        sender = self.get_param('parameters.sender')
        if sender is None:
            self.return_error_message(message.format("sender", "parameters"))
        recipients = self.get_param('parameters.recipients')
        if recipients is None:
            self.return_error_message(message.format("recipients", "parameters"))
        severity = self.get_param('data.severity')
        if severity is None:
            self.return_error_message(message.format("severity", "data"))

        self.validate_args(language=language, sender=sender, recipients=recipients, severity=severity)

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
                is_mail_alert=True,
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
        mail_sender = mail.MailSender(server=self.smtp_server, port=self.smtp_port, username=self.smtp_username,
                                      passwd=self.smtp_password, ssl=self.smtp_ssl)

        try:
            mail_sender.send_msg(sender=sender, recipients=recipients, subject=subject, email_text=html_incident,
                                 attachments=[os.path.abspath(mapping_severity_to_images[severity]),
                                              os.path.abspath("mail/images/footerlogo.jpg")])
        except mail.MailException as err:
            self.return_error_message("Message not sent: {}".format(err))

        self.report({'message': 'Message send'})

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='message send')]


if __name__ == '__main__':
    Mail().run()
