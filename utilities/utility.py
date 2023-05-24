import os, sys
import logging
import traceback
from datetime import datetime
from snowflake.connector.pandas_tools import pd_writer
from sqlalchemy import create_engine
import json
import snowflake.connector
import snowflake.connector.errors
import base64
from utilities import query as qry

# from cryptography.fernet import Fernet
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from office365.runtime.auth.authentication_context import AuthenticationContext
# from office365.sharepoint.client_context import ClientContext
# from office365.sharepoint.files.file import File
# # for salesforce
# from simple_salesforce import Salesforce
# import utilities.read_encrypted_config as decrypt_func
# from exchangelib import DELEGATE, Account, Credentials, Message, OAuth2Credentials
# from exchangelib import FileAttachment, Mailbox, Configuration, Folder, ItemAttachment
# from exchangelib import Credentials, Account, Version, Configuration, Build, OAUTH2, IMPERSONATION, DELEGATE, Identity
# from exchangelib.version import Version, EXCHANGE_O365
# from exchangelib.properties import HTMLBody
# from utilities import querys as qry
# import io

# converting encrypting config to its base
# cfg = decrypt_func.decrypt_config_file()
with open(r"utilities\db_config.json", "r") as fd:
    cfg = json.loads(fd.read())
    cfg = cfg["DG"]
print("cfg", cfg)

'''class Sharepoint:
    """
    This class is used to get the connection of
    sharepoint team site directory and gives the credential of
    given sharepoint team site, so that we can read the file
    inside the sharepoint team site.
    """

    def __init__(self, dir_name, file_name):
        self.sharepoint_url = cfg[qry.CONFIG_TYPE]["sharepoint_url"]
        self.sharepoint_username = cfg[qry.CONFIG_TYPE]["sharepoint_username"]
        self.sharepoint_password = cfg[qry.CONFIG_TYPE]["sharepoint_password"]
        self.folder_in_sharepoint = cfg[qry.CONFIG_TYPE]["folder_in_sharepoint"]
        self.dir_name = dir_name
        self.file_name = file_name
        self.response = None

    def sharepoint_auth(self):
        auth = AuthenticationContext(self.sharepoint_url)
        auth.acquire_token_for_user(self.sharepoint_username, self.sharepoint_password)
        ctx = ClientContext(self.sharepoint_url, auth)
        web = ctx.web
        ctx.load(web)
        ctx.execute_query()
        print('Connected to SharePoint: ', web.properties['Title'])
        return ctx

    def download_file(self):
        ctx = self.sharepoint_auth()
        # sharepoint_file = self.folder_in_sharepoint + "/" + dir_name + "/" + file_name
        sharepoint_file = self.folder_in_sharepoint + self.dir_name + "/" + self.file_name
        print("sharepoint_file", sharepoint_file)
        self.response = File.open_binary(ctx, sharepoint_file)
        # return response

    def read_from_url(self):
        self.download_file()
        byte_file_obj = io.BytesIO()
        byte_file_obj.write(self.response.content)
        byte_file_obj.seek(0)
        return byte_file_obj

'''
'''def read_json(filename):
    """
    This Function will the read the json file
    and return the content of the given json file.
    """
    with open(filename, "r") as fd:
        data = json.loads(fd.read())
    return data'''

'''def cleanup_folder(dir_name):
    """
    This Function will remove all the files
    present at given directory.
    """
    for d, _, f in os.walk(dir_name):
        for f_name in f:
            filepath = os.path.join(d, f_name)
            print(f"Removing files {filepath}")
            os.remove(filepath)

'''
'''def clean_directory(dir_name):
    """
    This Function will clean up the directory if the size of Directory is >450 MB.
    """
    size = 0
    for path, dirs, files in os.walk(dir_name):
        for f in files:
            fp = os.path.join(path, f)
            size += os.path.getsize(fp)
    size = size / (1024 * 1024)
    if size > 450:
        print(f"clean up the directory {dir_name}")
        cleanup_folder(dir_name)
    # return size / (1024 * 1024)

'''
'''def create_data_source_structure():
    """
    This function will create the data source
    structure as it required for script to execute from it.
    """
    source_dir = os.listdir(qry.DATA_SOURCE_DIR)
    new_source_dir = qry.DATA_SOURCE_DIR_STRUCTURE
    res = set(new_source_dir) - set(source_dir)
    if len(res) > 0:
        for i in res:
            os.mkdir(os.path.join(qry.DATA_SOURCE_DIR, i))
            print(f"Data Source Directory Name {i} Created Successfully.")
    # end if

'''
'''def output_dir_create():
    output_dir = qry.MODEL_OUTPUT_DATA_SOURCE_DIR_STRUCTURE
    if output_dir in os.listdir(os.getcwd()):
        pass
    else:
        os.mkdir(os.path.join("ModelOutput"))
'''

'''def generate_base64_token(pas):
    pass_64_byte = base64.b64encode(pas.encode())
    return pass_64_byte

'''
'''def generate_token(pas):
    password = b"secret key"
    # hashes.MD5()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(hkdf.derive(password))
    decode_key = Fernet(key)
    sc_key = str.encode(pas)
    token = decode_key.encrypt(sc_key)
    return token, decode_key

'''


def cleanup_environment(engine, conn):
    """
    This function will close the connection of
    snowflake instance.
    """
    engine.close()
    conn.close()
    print(f"Closing connection of snowflake")


def snowflake_database_connection(db=cfg[qry.CONFIG_TYPE]["database"], schema=cfg[qry.CONFIG_TYPE]["schema"]):
    account_identifier = cfg[qry.CONFIG_TYPE]["account"]
    user = cfg[qry.CONFIG_TYPE]["user"]
    # password = generate_base64_token(cfg[qry.CONFIG_TYPE]["password"])
    password = cfg[qry.CONFIG_TYPE]["password"]
    database_name = db
    schema_name = schema
    print("schema name", schema_name)
    print("password", password)
    conn_string = f"snowflake://{user}:{password}@{account_identifier}/{database_name}/{schema_name}"
    engine = create_engine(conn_string)
    engine = engine.connect()
    conn = snowflake.connector.connect(user=user, password=password,
                                       account=account_identifier, database=database_name, schema=schema_name,
                                       role="accountadmin")
    print("Database successfully connected... ")
    return engine, conn


'''class Mylogger:
    def __init__(self, logpath='logger.log'):
        self.logPath = logpath
        self.logger = logging.getLogger('exc_logger')
        self.logger.setLevel(logging.INFO)
        # self.logPath = self.logpath
        # create a file to store all the
        # logged exceptions
        logfile = logging.FileHandler(self.logPath)

        fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        formatter = logging.Formatter(fmt)

        logfile.setFormatter(formatter)
        self.logger.addHandler(logfile)

    def create_logger(self):
        return self.logger

'''
'''def write_error_log(query, error_msg):
    with open("PxS_Detail_Error.txt", "a") as logf:
        print("in write_error_log")
        logf.write("\n******************************************************************\n")
        logf.write("Failed at- %s" % datetime.now())
        logf.write(query + '\n' + error_msg)
        logf.write("\n******************************************************************\n")


def exception_handler(func_obj=None, loggerObj=None):
    def wrapper(func):
        def inner_function(*args, **kwargs):
            value = None
            flag = 1
            try:
                value = func(*args, **kwargs)
            except Exception as err:
                value = "Exception Occurred Function\n"
                flag = 0
                exc_type, exc_value, exc_traceback = sys.exc_info()
                query = "[Inputs - " + str([arg for arg in args if len(args) > 1]) + "]"
                error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
                value += error_msg
                content = "To get the more details. Please visit PxS_Error_Log.txt file.\n"
                heading = "Some Error occurred. \n"
                msg = heading + str(exc_value) + " Error, for data model name " + str(func.__name__) + " : " \
                      + content
                loggerObj.error(exc_value)
                value = {"status": repr(err)}
                write_error_log(query, error_msg)
                value = json.dumps(value)
                EMAIL().send_data_model_failure(source_name=str(func.__name__), msg=msg)
            return value, flag, func_obj

        return inner_function

    return wrapper


class SalesforceLogin:

    def __init__(self, acType="dev"):
        self.sfUsername = cfg[acType]["sf_user_name"]
        self.sfPassword = cfg[acType]["sf_password"]
        self.sfSecurityToken = cfg[acType]["sf_security_token"]

    def sf_login(self):
        sf = Salesforce(username=self.sfUsername, password=self.sfPassword,
                        security_token=self.sfSecurityToken, domain='test')
        return sf

    # def sf_download_data(self, reportid):
    #     sf = self.sf_login()
    #     return df


# define the EMAIL CLASS
class EMAIL:
    username = cfg[qry.CONFIG_TYPE]["service_account_user"]
    password = cfg[qry.CONFIG_TYPE]["sharepoint_password"]
    email = cfg[qry.CONFIG_TYPE]["service_account_user"]
    client_id = cfg[qry.CONFIG_TYPE]["service_account_client_id"]
    tenant_id = cfg[qry.CONFIG_TYPE]["service_account_tenant_id"]
    client_secrets = cfg[qry.CONFIG_TYPE]["service_account_client_secrets"]

    # Initialization
    def __init__(self):
        self.username = self.username
        self.password = self.password
        self.email = self.email
        self.client_id = self.client_id
        self.tenant_id = self.tenant_id
        self.client_secrets = self.client_secrets
        self.subject = None
        self.account = None
        self.message = None
        self.body = None
        self.myfile = None
        self.to_recipients = []
        self.cc_recipients = []
        self.bcc_recipients = []
        self.mail_credentials = None
        self.mail_config = None
        # print(f"self.client_id {self.client_id}, self.tenant_id {self.tenant_id},"
        #       f" self.client_secrets {self.client_secrets}")

    # Adding recipients function
    def add_recipients(self, to_recipients, cc_recipients=None, bcc_recipients=None):
        if cc_recipients is not None:
            self.cc_recipients.extend(cc_recipients)

        if bcc_recipients is not None:
            self.bcc_recipients.extend(bcc_recipients)

        self.to_recipients.extend(to_recipients)

    # Adding message subject & body function
    def add_message(self, subject, body):
        self.email = self.email
        self.subject = subject
        self.body = body
        self.mail_credentials = OAuth2Credentials(
            client_id=self.client_id, client_secret=self.client_secrets, tenant_id=self.tenant_id,
            identity=Identity(smtp_address=self.username)
        )
        self.mail_config = Configuration(
            credentials=self.mail_credentials, auth_type=OAUTH2,
            server="outlook.office365.com", version=Version(build=EXCHANGE_O365),
        )
        self.account = Account(primary_smtp_address=self.email,
                               config=self.mail_config, autodiscover=False)
        try:
            if len(self.bcc_recipients) == 0 and len(self.cc_recipients) == 0 and len(self.to_recipients) != 0:
                self.message = Message(account=self.account
                                       , folder=self.account.sent
                                       , subject=self.subject
                                       , body=self.body
                                       , to_recipients=self.to_recipients)

            elif len(self.cc_recipients) == 0:
                self.message = Message(account=self.account
                                       , folder=self.account.sent
                                       , subject=self.subject
                                       , body=self.body
                                       , to_recipients=self.to_recipients
                                       , bcc_recipients=self.bcc_recipients)

            elif len(self.bcc_recipients) == 0:
                self.message = Message(account=self.account
                                       , folder=self.account.sent
                                       , subject=self.subject
                                       , body=self.body
                                       , to_recipients=self.to_recipients
                                       , cc_recipients=self.cc_recipients)
        except:  # MissingEmail
            print('Missing recipients email addresses.')

    # Adding attachment
    def add_attachment(self, file, name):
        with open(file, 'rb') as f:
            content = f.read()
        self.myfile = FileAttachment(name=name, content=content)
        self.message.attach(self.myfile)

    # Sending mail
    def send_mail(self):
        self.message.send_and_save()

    # sending send_success_metric_mail
    

    
    def send_email_notification_business_team(self, source_name, month_year, msg):
        # obj = EMAIL()
        schedular = read_json(r"utilities/data_source_schedular.json")
        self.add_recipients(to_recipients=schedular["business_team_email"],
                            cc_recipients=schedular["metric_success_email"])
        self.add_message(subject=f"PXS DASHBOARD: Reminder Data Source:"
                                 f" {source_name} for {month_year[0]} {month_year[1]} to Send",
                         body=HTMLBody(msg))
        self.send_mail()
        print(f"Mail sent for {source_name},successfully.")

    def send_email_notification_business_team_aa(self, source_name, month_year, msg):
        # obj = EMAIL()
        schedular = read_json(r"utilities/data_source_schedular.json")
        self.add_recipients(to_recipients=schedular["business_team_email_aa"],
                            cc_recipients=schedular["metric_success_email"])
        self.add_message(subject=f"PXS DASHBOARD: Reminder Data Source:"
                                 f" {source_name} for {month_year[0]} {month_year[1]} to Send",
                         body=HTMLBody(msg))
        self.send_mail()
        print(f"Mail sent for {source_name},successfully.")

    def send_data_source_status(self, msg, which_month):
        # obj = EMAIL()
        schedular = read_json(r"utilities/data_source_schedular.json")
        self.add_recipients(to_recipients=["deepak.gupta-cw@otsuka-us.com"])
        # obj.add_recipients(to_recipients=["pxs_support@otsuka-us.com"],
        #                    cc_recipients=["deepak.gupta-cw@otsuka-us.com"])
        self.add_message(subject=f"PXS DASHBOARD: Reminder to update the Data Source for {which_month} Month.",
                         body=HTMLBody(msg))
        self.send_mail()
        print(f"Mail sent for successfully.")


class DownloadAttachment:
    username = cfg[qry.CONFIG_TYPE]["service_account_user"]
    password = cfg[qry.CONFIG_TYPE]["sharepoint_password"]
    email = cfg[qry.CONFIG_TYPE]["service_account_user"]
    client_id = cfg[qry.CONFIG_TYPE]["service_account_client_id"]
    tenant_id = cfg[qry.CONFIG_TYPE]["service_account_tenant_id"]
    client_secrets = cfg[qry.CONFIG_TYPE]["service_account_client_secrets"]

    def __init__(self):
        self.username = self.username
        self.password = self.password
        self.email = self.email
        self.account = None
        self.client_id = self.client_id
        self.tenant_id = self.tenant_id
        self.client_secrets = self.client_secrets

    def connect_email_server(self):
        # mail_credentials = Credentials(username=self.username, password=self.password)
        mail_credentials = OAuth2Credentials(
            client_id=self.client_id, client_secret=self.client_secrets, tenant_id=self.tenant_id,
            identity=Identity(smtp_address=self.username)
        )
        # mail_config = Configuration(server='outlook.office365.com', credentials=mail_credentials)
        mail_config = Configuration(
            credentials=mail_credentials, auth_type=OAUTH2,
            server="outlook.office365.com", version=Version(build=EXCHANGE_O365),
        )
        self.account = Account(primary_smtp_address=self.email,
                               config=mail_config, autodiscover=False)
        # some_folder = account.inbox.all().order_by('-datetime_received')[:100000]
        # return some_folder

    def download_attachment(self, sub, data_source_name, file_name):
        self.connect_email_server()
        # items = self.account.inbox.filter(author=sender_name)
        items = self.account.inbox.all().order_by('-datetime_received')[:30]
        root_dir = qry.DATA_SOURCE_DIR  # r"DataSource"
        local_path = os.path.join(root_dir, data_source_name)
        flag = None
        for item in items:
            print(f"Looking for subject: {sub} and File Name: {file_name} in mailbox")
            if sub.lower().replace(" ", "") == item.subject.lower().replace(" ", ""):
                flag = "subject matched"
                # print("item.subject", item.subject)
                flag = -4
                print("len of attachment", len(item.attachments))
                if len(item.attachments) > 0:
                    for attachment in item.attachments:
                        if isinstance(attachment, FileAttachment):
                            if file_name.lower().replace(" ", "") in attachment.name.lower().replace(" ", ""):
                                # print("subject of Mail: ", item.subject)
                                # print("attachment.name: ", attachment.name)
                                local_path = os.path.join(local_path, attachment.name)
                                with open(local_path, 'wb') as f:
                                    f.write(attachment.content)
                                heading = f"File '{attachment.name}', downloaded Successfully for Data Model {data_source_name} at Location {local_path}. \n"
                                ending = "\n **** This Email is Auto Generated. Please Do not Reply. ****\nRegards PXS Team, " \
                                         "\nThank You! "
                                # full_message = f"{heading + ending}"
                                full_message = f"{heading}"
                                # EMAIL().send_download_success
                                #
                                # (full_message)
                                # print(heading)
                                flag = local_path, full_message
                                # print("flag", flag)
                                return flag
                            else:
                                # print(f"file {file_name} not attachment in mail.")
                                flag = -2
                    # end for
                else:
                    flag = -4  # attachment is not present
                    # print("attachment is not present flag", flag)
                    break
            else:
                flag = -3  # subject did not match
                # print("subject did not match", flag)
                # end if
                # end for

            # end if
        return flag
        # end for
'''
