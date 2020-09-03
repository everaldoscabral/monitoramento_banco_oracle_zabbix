#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Envio de gráfico por Email através do ZABBIX (Send zabbix alerts graph mail)
#
#
# Copyright (C) <2016>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Contacts:
# Eracydes Carvalho (Sansão Simonton) - Monitoring Specialist - Telegram: @sansaoipb
# Thiago Paz - NOC Analyst - thiagopaz1986@gmail.com

import os, sys, re, json, time, smtplib, urllib3
import requests
from pyrogram import Client

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from configparser import ConfigParser
from urllib.parse import quote

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

class PropertiesReaderX:
    config = None
    def __init__(self, pathToProperties):
        PropertiesReaderX.config = ConfigParser()
        PropertiesReaderX.config.read(pathToProperties)

    def getValue(self, section, key):
        # type: (object, object) -> object
        return PropertiesReaderX.config.get(section, key)

    def setValue(self, section, key, value):
        PropertiesReaderX.config.set(section, key, value)
        return PropertiesReaderX.config.get(section, key)

if sys.platform.startswith('win32') or sys.platform.startswith('cygwin') or sys.platform.startswith('darwin'):  # para debug quando estiver no WINDOWS ou no MAC
    path = os.path.join(os.getcwd(), "{0}")
    graph_path = os.getcwd()

else:
    path = "/usr/local/share/zabbix/alertscripts/"

    if not os.path.exists(path):
        path = "/usr/lib/zabbix/alertscripts/{0}"
    else:
        path = "/usr/local/share/zabbix/alertscripts/{0}"
    graph_path = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'path.graph')  # Path where graph file will be save temporarily

# Zabbix settings | Dados do Zabbix ####################################################################################
zbx_server = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'url')
zbx_user = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'user')
zbx_pass = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'pass')

# Graph settings | Configuracao do Grafico #############################################################################
height = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'height')    # Graph height | Altura
width = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'width')     # Graph width  | Largura

# Salutation | Saudação ################################################################################################
Salutation = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'salutation')
if re.search("(sim|s|yes|y)", str(Salutation).lower()):
    hora = int(time.strftime("%H"))

    if hora < 12:
        salutation = 'Bom dia'
    elif hora >= 18:
        salutation = 'Boa noite'
    else:
        salutation = 'Boa tarde'
else:
    salutation = ""


def keepass(value=None):
    import random
    char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#-_=+,.;:?"
    passwd = ""
    if value:
        char1 = value
    else:
        char1 = len(char)

    while len(passwd) != char1:
         passwd += random.choice(char)
    return passwd

def encrypt(key, source, encode=True):
    source = source.encode("ISO-8859-1")
    key = SHA256.new(key.encode("ISO-8859-1")).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("ISO-8859-1") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("ISO-8859-1"))
    key = SHA256.new(key.encode("ISO-8859-1")).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding].decode("ISO-8859-1")  # remove the padding

# Diretórios
# Log path | Diretório do log
projeto = "notificacoes"
logName = '{0}Graph-JsonX.log'.format(projeto)
pathLogs = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'path.logs')

if "default" == pathLogs.lower():
    pathLogs = path.format("log")

arqLog = "{0}".format(os.path.join(pathLogs, logName))

if not os.path.exists(pathLogs):
    os.makedirs(pathLogs)

########################################################################################################################
########################################################################################################################
########################################################################################################################
########################################################################################################################
fileC = """{
    "code": false,
    "email": {
            "smtp.server": false,
            "mail.user": false,
            "mail.pass": false
    },
    "telegram": {
            "api.id": false,
            "api.hash": false
    },
    "whatsapp": {
        "line": false,
        "acessKey": false,
        "port": false
    }
}"""

import logging.config
import traceback

file = """{
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
        "simple": {
            "format": "[%(asctime)s][%(levelname)s] - %(message)s"
        }
    },

    "handlers": {
        "file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "maxBytes": 5242880,
            "backupCount":5,
            "level": "INFO",
            "formatter": "simple",
            "filename": "python_logging.log",
            "encoding": "utf8"
        }
    },

    "root": {
        "level": "INFO",
        "handlers": ["file_handler"]
    }
}
"""

arqConfig = "logging_configuration.json"
pathDefault = ""

class Log:
    @staticmethod
    def writelog(entry, pathfile, log_level):
        global pathDefault

        try:
            Log.log(entry, pathfile, log_level)
        except Exception:
            try:
                # if "\\" in traceback.format_exc():
                #     linha = re.search("(File)[A-Za-z0-9_\"\\\\\s:.]+", traceback.format_exc()).group()[5:].replace("\"", "")
                #     pathDefault = "{0}\\log\\".format("\\".join(linha.split("\\")[:-1]))
                # else:
                #     linha = re.search("(File)[A-Za-z0-9_\"/\s:.]+", traceback.format_exc()).group()[5:].replace("\"", "")
                #     pathDefault = "{0}/log/".format("/".join(linha.split("/")[:-1]))

                pathDefault = f"{pathLogs}/"
                arquivo = open("{0}{1}".format(pathDefault, arqConfig), "w")
                arquivo.writelines(file)
                arquivo.close()
                Log.log(entry, pathfile, log_level)
            except Exception:
                pass

    @staticmethod
    def log(entry, pathfile, log_level):
        logging.getLogger('suds.client').setLevel(logging.CRITICAL)
        logging.getLogger('suds.wsdl').setLevel(logging.CRITICAL)
        with open("{0}{1}".format(pathDefault, arqConfig), 'r+') as logging_configuration_file:
            config_dict = json.load(logging_configuration_file)
            config_dict["handlers"]["file_handler"]['filename'] = pathfile
        logging.config.dictConfig(config_dict)
        logger = logging.getLogger(__name__)
        logging.getLogger("suds").setLevel(logging.CRITICAL)

        if log_level.upper() == "INFO":
            logger.info(str(entry))
        elif log_level.upper() == "WARNING":
            logger.warning(str(entry))
        elif log_level.upper() == "CRITICAL":
            logger.critical(str(entry))
        elif log_level.upper() == "ERROR":
            logger.error(str(entry))

log = Log

nograph = "nograph"

def destinatarios(dest):
    destinatario = ["{0}".format(hostsW).strip().rstrip() for hostsW in dest.split(",")]
    return destinatario

def send_mail(dest, itemType, get_graph, key, jsonX):
    # Mail settings | Configrações de e-mail ###########################################################################
    email_from = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'email.from')
    smtp_server = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'smtp.server')
    mail_user = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'mail.user')
    mail_pass = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionEmail', 'mail.pass')
    ####################################################################################################################
    if jsonX['smtp.server']:
        smtp_server = decrypt(key, smtp_server)

    if jsonX['mail.user']:
        mail_user = decrypt(key, mail_user)

    if jsonX['mail.pass']:
        mail_pass = decrypt(key, mail_pass)

    try:
        email_from = email.utils.formataddr(tuple(email_from.replace(">", "").split(" <")))
    except:
        email_from = email_from

    dests = ', '.join(dest)
    msg = body
    msg = msg.replace("\\n", "").replace("\n", "<br>")
    try:
        Subject = re.sub(r"(<(\/)?[a-z]>)", "", subject)
    except:
        Subject = subject

    msgRoot = MIMEMultipart('related')
    msgRoot['Subject'] = Subject
    msgRoot['From'] = email_from
    msgRoot['To'] = dests

    msgAlternative = MIMEMultipart('alternative')
    msgRoot.attach(msgAlternative)

    saudacao = salutation
    if saudacao:
        saudacao = "<p>{0},</p>".format(salutation)
    else:
        saudacao = ""

    text = '{0}<p>{1}</p>'.format(saudacao, msg)

    if re.search("(0|3)", itemType):
        URL = "{0}/history.php?action=showgraph&itemids[]={1}"
        text += '<br><a href="{0}"><img src="cid:image1"></a>'.format(URL.format(zbx_server, itemid))
        msgImage = MIMEImage(get_graph.content)
        msgImage.add_header('Content-ID', '<image1>')
        msgRoot.attach(msgImage)

    msgText = MIMEText(text, 'html', _charset='utf-8')
    msgAlternative.attach(msgText)

    try:
        smtp = smtplib.SMTP(smtp_server)
        smtp.ehlo()

        try:
            smtp.starttls()
        except Exception:
            pass

        try:
            smtp.login(mail_user, mail_pass)
        except smtplib.SMTPAuthenticationError as msg:
            print("Error: Unable to send email | Não foi possível enviar o e-mail - {0}".format(msg.smtp_error.decode("utf-8").split(". ")[0]))
            log.writelog('Error: Unable to send email | Não foi possível enviar o e-mail - {0}'.format(msg.smtp_error.decode("utf-8").split(". ")[0]), arqLog, "WARNING")
            smtp.quit()
            exit()
        except smtplib.SMTPException:
            pass

        try:
            smtp.sendmail(email_from, dest, msgRoot.as_string())
        except Exception as msg:
            print("Error: Unable to send email | Não foi possível enviar o e-mail - {0}".format(msg.smtp_error.decode("utf-8").split(". ")[0]))
            log.writelog('Error: Unable to send email | Não foi possível enviar o e-mail - {0}'.format(msg.smtp_error.decode("utf-8").split(". ")[0]), arqLog,
                         "WARNING")
            smtp.quit()
            exit()

        print("Email sent successfully | Email enviado com sucesso ({0})".format(dests))
        log.writelog('Email sent successfully | Email enviado com sucesso ({0})'.format(dests), arqLog, "INFO")
        smtp.quit()
    except smtplib.SMTPException as msg:
        print("Error: Unable to send email | Não foi possível enviar o e-mail ({0})".format(msg))
        log.writelog('Error: Unable to send email | Não foi possível enviar o e-mail ({0})'.format(msg), arqLog, "WARNING")
        logout_api()
        smtp.quit()
        exit()

def send_telegram(dest, itemType, get_graph, key, jsonX):
    # Telegram settings | Configuracao do Telegram #########################################################################
    api_id = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'api.id')
    api_hash = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'api.hash')

    if jsonX['api.id']:
        api_id = int(decrypt(key, api_id))

    if jsonX['api.hash']:
        api_hash = str(decrypt(key, api_hash))

    app = Client("SendGraph", api_id=api_id, api_hash=api_hash)

    dest = dest.lower()
    saudacao = salutation
    if saudacao:
        # saudacao = salutation + " {0} \n\n"
        saudacao = salutation + " <b><u>{0}</u></b> \n\n"
    else:
        saudacao = ""

    if re.search("user#|chat#|\'|\"", dest):
        if "#" in dest:
            dest = dest.split("#")[1]

        elif dest.startswith("\"") or dest.startswith("\'"):
            dest = dest.replace("\"", "").replace("\'", "")

    elif dest.startswith("@"):
        dest = dest[1:]

    with app:
        flag = True
        while flag:
            try:
                Contatos = app.get_contacts()
                for contato in Contatos:
                    try:
                        Id = f"{contato.id}"
                        nome = f"{contato.first_name} {contato.last_name}"
                    except:
                        print("Sua versão do Python é '{}', atualize para no mínimo 3.6".format(sys.version.split(" ", 1)[0]))
                        exit()

                    username = contato.username
                    if username:
                        if username.lower() in dest or dest in Id or dest in nome.lower():
                            dest = nome
                            flag = False
                            break
                    else:
                        if dest in Id or dest in nome.lower():
                            dest = nome
                            flag = False
                            break
            except:
                pass

            try:
                if flag:
                    Dialogos = app.iter_dialogs()
                    for dialogo in Dialogos:
                        Id = f"{dialogo.chat.id}"
                        nome = "{}".format(dialogo.chat.title or f"{dialogo.chat.first_name} {dialogo.chat.last_name}")
                        username = dialogo.chat.username

                        if username:
                            if username in dest or dest in Id or dest in nome.lower():
                                dest = nome
                                flag = False
                                break
                        else:
                            if dest in Id or dest in nome.lower():
                                dest = nome
                                flag = False
                                break
            except:
                flag = False
                try:
                    chat = app.get_chat(dest)
                    Id = "{}".format(chat.id)
                    dest = "{}".format(chat.title or f"{chat.first_name} {chat.last_name}")
                except Exception as msg:
                    print(msg.args[0])
                    log.writelog(f'{msg.args[0]}', arqLog, "ERROR")
                    exit()

        sendMsg = """{}{} {}""".format(saudacao.format(dest), subject, body)
        if re.search("(0|3)", itemType):
            try:
                graph = '{0}/{1}.png'.format(graph_path, itemid)
                with open(graph, 'wb') as png:
                    png.write(get_graph.content)
            except BaseException as e:
                log.writelog('{1} >> An error occurred at save graph file in {0} | Ocorreu um erro ao salvar o grafico no diretório {0}'.format(graph_path, str(e)), arqLog, "WARNING")
                logout_api()
                exit()

            try:
                app.send_photo(Id, graph, caption=sendMsg, parse_mode="html")
                print('Telegram sent successfully | Telegram enviado com sucesso ({0})'.format(dest))
                log.writelog('Telegram sent successfully | Telegram enviado com sucesso ({0})'.format(dest), arqLog, "INFO")
            except Exception as e:
                print('Telegram FAIL at sending photo message | FALHA ao enviar a mensagem com gráfico pelo telegram\n%s' % e)
                log.writelog('{0} >> Telegram FAIL at sending photo message | FALHA ao enviar a mensagem com gráfico pelo telegram ({1})'.format(e, dest), arqLog, "ERROR")
                logout_api()
                exit()

            try:
                os.remove(graph)
            except Exception as e:
                print(e)
                log.writelog('{0}'.format(str(e)), arqLog, "ERROR")

        else:
            try:
                app.send_message(Id, sendMsg, parse_mode="html")
                print('Telegram sent successfully | Telegram enviado com sucesso ({0})'.format(dest))
                log.writelog('Telegram sent successfully | Telegram enviado com sucesso ({0})'.format(dest), arqLog, "INFO")
            except Exception as e:
                print('Telegram FAIL at sending photo message | FALHA ao enviar a mensagem com gráfico pelo telegram\n%s' % e)
                log.writelog('{0} >> Telegram FAIL at sending message | FALHA ao enviar a mensagem pelo telegram ({1})'.format(e, dest), arqLog, "ERROR")
                logout_api()
                exit()

def token():
    try:
        login_api = requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
            verify=False, data=json.dumps(
                {
                  "jsonrpc": "2.0",
                  "method": "user.login",
                  "params": {
                      "user": zbx_user,
                      "password": zbx_pass
                  },
                  "id": 1
                }
            )
        )

        login_api = json.loads(login_api.text.encode('utf-8'))

        if 'result' in login_api:
            auth = login_api["result"]
            return auth

        elif 'error' in login_api:
            print('Zabbix: %s' % login_api["error"]["data"])
            exit()
        else:
            print(login_api)
            exit()

    except ValueError as e:
        print('Check declared zabbix URL/IP and try again | Valide a URL/IP do Zabbix declarada e tente novamente\nCurrent: %s' % zbx_server)
        log.writelog('Check declared zabbix URL/IP and try again | Valide a URL/IP do Zabbix declarada e tente novamente. (Current: {0})'.format(zbx_server), arqLog, "WARNING")
        exit()
    except Exception as e:
        print(e)
        log.writelog('{0}'.format(str(e)), arqLog, "WARNING")
        exit()

def version_api():
    resultado = requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
        verify=False, data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "apiinfo.version",
                    "params": [],
                    "id": 5
                }
        )
    )
    resultado = json.loads(resultado.content)
    if 'result' in resultado:
        resultado = resultado["result"]
    return resultado

def logout_api():
    requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
        verify=False, data=json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "user.logout",
                "params": [],
                "auth": auth,
                "id": 4
            }
        )
    )

def getgraph():
    stime = int(PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSection', 'stime'))  # Graph start time [3600 = 1 hour ago]  |  Hora inicial do grafico [3600 = 1 hora atras]
    try:
        loginpage = requests.get(f'{zbx_server}/index.php', auth=(zbx_user, zbx_pass), verify=False).text
        enter = re.search('<button.*value=".*>(.*?)</button>', loginpage)
        s = requests.Session()

        try:
            enter = str(enter.group(1))
            s.post(f'{zbx_server}/index.php?login=1', params={'name': zbx_user, 'password': zbx_pass, 'enter': enter},verify=False).text
        except:
            pass

        stime = time.strftime("%Y%m%d%H%M%S", time.localtime(time.time() - stime))

        get_graph = s.get('%s/chart3.php?name=%s&period=%s&width=%s&height=%s&stime=%s&items[0][itemid]=%s&items[0][drawtype]=5&items[0][color]=%s' % (
            zbx_server, itemname, period, width, height, stime, itemid, color))

        sid = s.cookies.items()[0][1]
        s.post('{0}/index.php?reconnect=1&sid={1}'.format(zbx_server, sid))

        return get_graph

    except BaseException:
        log.writelog('Can\'t connect to {0}/index.php | Não foi possível conectar-se à {0}/index.php'.format(zbx_server), arqLog, "CRITICAL")
        logout_api()
        exit()

def getItemType():
    try:
        limit = 1000
        itemid = requests.post(f'{zbx_server}/api_jsonrpc.php', headers={'Content-type': 'application/json'},
            verify=False, data=json.dumps(
                   {
                       "jsonrpc": "2.0",
                       "method": "item.get",
                       "params": {
                           "output": ["itemid", "name", "lastvalue", "value_type"],
                           "limit": limit,
                           "sortfield": "itemid",
                           "sortorder": "DESC"
                       },
                       "auth": auth,
                       "id": 3
                   }
            )
        )

        ValuesItemid = ()
        ValueItemid = json.loads(itemid.content)
        if 'result' in ValueItemid:
            resultado = ValueItemid["result"]
            for i in range(0, len(resultado)):
                if resultado[i]['lastvalue'] != '0' and re.search("(0|3)", resultado[i]['value_type']):
                    if resultado[i]['lastvalue']:
                        ValuesItemid += (resultado[i]['itemid'], resultado[i][u'name'], resultado[i]['value_type'])
                        break

        return ValuesItemid

    except Exception as msg:
        print(msg)

def get_info(key, jsonX, name=None):
    # Telegram settings | Configuracao do Telegram #########################################################################
    api_id = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'api.id')
    api_hash = PropertiesReaderX(path.format('configScripts.properties')).getValue('PathSectionTelegram', 'api.hash')

    if jsonX['api.id']:
        api_id = int(decrypt(key, api_id))

    if jsonX['api.hash']:
        api_hash = str(decrypt(key, api_hash))

    app = Client("SendGraph", api_id=api_id, api_hash=api_hash)
    ContA = 0
    with app:
        infos = ""
        try:
            dialogos = app.iter_dialogs()
        except Exception as msg:
            if "BOT" in msg.args[0]:
                print("Esta função não está disponível para consultas com BOT\n")
            else:
                print(msg.args[0])
            exit()

        infos += ""
        if name:
            for dialogo in dialogos:
                Id = "Id: {}".format(dialogo.chat.id)
                if dialogo.chat.title:
                    nome = "Nome: {}".format(dialogo.chat.title)
                else:
                    username = dialogo.chat.username
                    nome = "Nome: {} {}\nNonde de usuário: {}".format(dialogo.chat.first_name, dialogo.chat.last_name, username)
                if name.lower() in nome.lower() or name in Id:
                    if "" == infos:
                        infos += "\nChats encontrados (ContA):\n\n"

                    infos += "{}\n{}\n\n".format(Id, nome)
                    ContA += 1

            if not infos:
                infos = "Não há registros referente à \"{}\"\n".format(name)

        else:
            infos += "\nChats encontrados (ContA):\n\n"
            for dialogo in dialogos:
                infos += "{}\n".format(dialogo.chat.title or dialogo.chat.first_name)
                ContA += 1

        if ContA == 1:
            infos = re.sub("Chats encontrados \(ContA\)", f"Único chat encontrado", infos)

        infos = re.sub("ContA", f"{ContA}", infos)

    return infos

def get_cripto():
    fileX = os.path.join(pathLogs, ".env.json")
    if not os.path.exists(fileX):
        os.popen(f"cat >> {fileX} << EOF\n{fileC}\nEOF")

    JsonX = json.loads(os.popen(f"cat {fileX}").read())
    # import ipdb; ipdb.set_trace()
    textK0 = []
    text = ""
    for obj in JsonX:
        if "code" == obj:
            if not JsonX[obj]:
                JsonX[obj] = keepass()
            continue
        textK = ""
        for k in JsonX[obj]:
            if not JsonX[obj][k]:
                if not text:
                    text += "Os seguintes itens não estão criptografados:\n\n"
                if not textK:
                    textK += f"{obj}: "
                textK += f"{k}, "
                textK0 += [k]

        if textK:
            text += f"{textK[:-2]}\n"

    JsonX = json.dumps(JsonX)
    os.popen(f"cat > {fileX} << EOF\n{JsonX}\nEOF")
    return text, textK0, JsonX, fileX

def create_cripto():
    texto, textoKey, JsonX, fileX = get_cripto()
    JsonX = json.loads(JsonX)
    if texto:
        config = path.format('configScripts.properties')
        tupla = []
        resposta = input("\nExistem campos sem criptografia,\nDeseja criptografar (sim/não)? ")
        if re.match("(s|sim|y|yes)", resposta.lower()):
            textoKey = ", ".join(textoKey)
            print(f"\nOs seguintes campos podem ser criptografados:\n{textoKey}")
            criptoK = [str(objs).strip().rstrip() for objs in input("\ninforme quais deseja: ").split(",")]
            for crip in criptoK:
                valor = input(f"\nAgora informe um valor para o campo '{crip}': ")
                # import ipdb; ipdb.set_trace()
                tupla.append((crip, valor))
                for js in JsonX:
                    if "code" != js:
                        for k in JsonX[js]:
                            if not JsonX[js][k]:
                                if crip == k:
                                    JsonX[js][k] = True

            # import ipdb; ipdb.set_trace()
            contArq = os.popen("cat {}".format(config)).read()
            key = JsonX['code']
            for t in tupla:
                k, v = t
                valueC = encrypt(key, v)
                valueR = re.search(f"\n{k} ?= ?(.*)\n", contArq).group(1)
                contArq = re.sub(f"{valueR}", f"{valueC}", contArq)

            contArq = contArq.rstrip()
            os.popen(f"cat > {config} << EOF\n{contArq} \nEOF")

        Json = json.dumps(JsonX)
        arquivo = open("{0}".format(fileX), "w")
        arquivo.writelines(Json)
        arquivo.close()
    return JsonX

def main():
    global subject, body, itemid, itemname, period, color
    try:
        try:
            itemid, itemname, item_type = getItemType()
        except:
            print('User has no read permission on environment | Usuário sem permissão de leitura no ambiente')
            log.writelog('User has no read permission on environment | Usuário sem permissão de leitura no ambiente', arqLog, "WARNING")
            logout_api()
            exit()

        color = '00C800'
        period = 3600
        subject = '<b>testando o envio com o item</b>:'
        body = '{0}'.format(itemname)

        # if sys.version_info < (3, 0):
        #     body = itemname.encode('utf-8')

        dest = sys.argv[1]
        destino = destinatarios(dest)

        if nograph in sys.argv:
            item_type = "1"
            get_graph = ""
        else:
            get_graph = getgraph()

        emails = []

        for x in destino:
            if re.search("^.*@[a-z0-9]+\.[a-z]+(\.[a-z].*)?$", x.lower()):
                emails.append(x)

            else:
                telegram = x.replace("_", " ")
                send_telegram(telegram, item_type, get_graph, codeKey, jsonT)

        if [] != emails:
            send_mail(emails, item_type, get_graph, codeKey, jsonE)

    except Exception as msg:
        print(msg)

if __name__ == '__main__':
    JSON = create_cripto()
    codeKey = JSON['code']
    jsonT = JSON['telegram']
    jsonE = JSON['email']

    if "info" == sys.argv[1]:
        try:
            nome = sys.argv[2]
        except:
            nome = None

        r = get_info(codeKey, jsonT, nome)
        print(r)
        exit()

    else:
        auth = token()
        main()
        logout_api()
