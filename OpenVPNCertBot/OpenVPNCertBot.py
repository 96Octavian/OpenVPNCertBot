#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
"""
Manage your certificate on your VPN with this bot
"""

# TODO: Make files_container() thread safe
# TODO: Add license and credits
# TODO: Allow owner to remove users
# TODO: Improve instructions and info
# TODO: extract openvpn server info for client configuration (i.e. to populate Default.txt)
# TODO: Copy the authorized() and args for every function from the other bot

import json
import logging
import os
import shutil
from systemd.journal import JournaldLogHandler as JournalHandler
import subprocess
import sys
import threading

from signal import (signal, SIGINT, SIGTERM, SIGABRT, SIGUSR1, SIGUSR2)
from time import sleep

from telegram.ext import (Updater, CommandHandler, Filters)

# Enable logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',\
					level=logging.INFO)

logger = logging.getLogger(__name__)

log_fmt = logging.Formatter('%(levelname)s: %(message)s')
log_ch = JournalHandler(identifier='OpenVPNCertBot')
log_ch.setFormatter(log_fmt)
logger.addHandler(log_ch)

class files_container():
	def __init__(self):
		lock = threading.Lock()
		self.users = {}
		self.awaiting = {}

	def load_all(self):

		self.lock.acquire()

		with open('./files/users.json', 'r') as f:
			self.users = json.load(f)

		with open('./files/awaiting.json', 'r') as f:
			self.awaiting = json.load(f)

		self.lock.acquire()

		logger.debug("All files opened")
		return

	# To be called whenever a file is modified
	def store(self, file_var, name):
		self.lock.acquire()
		with open('./files/%s.json' % name, 'w') as json_file:
			json.dump(file_var, json_file, sort_keys=True, indent=4, separators=(',', ': '))
		self.lock.release()
		logger.debug("updated file %s.json", name)
		return

# Check if it is me
def authorized(update):
	if str(update.message.chat.id) == ADMIN:
		return True
	return False

# First message to be sent
def command_start(update, context):
	update.message.reply_text(text="Questo bot ti aiuterà a ricevere e rinnovare i tuoi certificati .ovpn.\n\
				 Dopo aver richiesto l'iscrizione, sarai approvato e riceverai un certificato.\n\
				 Questo sarà revocato dopo una settimana e dovrai richiederne uno nuovo.\n\
				 Questi sono i comandi a tua disposizione:\n\
				 <code>/subscribe</code>: richiedi l'iscrizione.\n\
				 <code>/request nome_certificato</code>: richiedi un certificato. Ogni utente può richiedere più di un certificato.\n\
				 <code>/revoke nome_certificato</code>: revoca il certificato.\n\
				 <code>/list</code>: elenca i tuoi certificati\
				 Per chiarimenti o consigli, non contattarmi, cavoli tuoi", parse_mode='HTML')
	return

# Ask for subscription
def command_subscribe(update, context):

	files.lock.acquire()

	# Check if it has already subscribed
	if str(update.message.from_user.id) in files.users:
		update.message.reply_text(text="Sei già iscritto.")
		return

	# Check if it is already in list for approval
	if str(update.message.from_user.id) in files.awaiting:
		update.message.reply_text(text="Grazie. La tua iscrizione è in attesa di convalida.")
		return

	# Add him to the waiting list
	files.awaiting[str(update.message.from_user.id)] = update.message.from_user.first_name

	update.message.reply_text(text="Grazie. La tua iscrizione è in attesa di convalida.")
	logger.info("Utente %s in attesa di convalida", str(update.message.from_user.id))

	# Inform me of a new subscriber
	message = "Utenti in attesa:\n"
	for line in files.awaiting:
		message += files.awaiting[line] + '\n'

	files.lock.release()

	context.bot.sendMessage(ADMIN, text=message)
	message = None

	files.store(files.awaiting, "awaiting")

	return

# Check pending subscribe requests
def command_check(update, context):

	# If the sender is not me, discard
	if not authorized(update):
		update.message.reply_text(text="Non sei autorizzato.")
		return

	files.lock.acquire()

	# Check if there are awaiting users
	if files.awaiting.keys():
		message = "Utenti in attesa:\n"
		for user_id in files.awaiting:
			message += files.awaiting[user_id] + '\n'
		context.bot.sendMessage(ADMIN, text=message)
		message = None
	else:
		context.bot.sendMessage(ADMIN, "Nessun utente in attesa di approvazione")

	files.lock.release()

	return

# Approve a user(s) subscribe request(s)
def command_approve(update, context):

	# If the sender is not me, discard
	if not authorized(update):
		context.bot.SendMessage(update.message.from_user.id, "Non sei autorizzato.")
		return

	# Copy the defaults.txt file
	shutil.copyfile("default.txt", "defaults/default_{}.txt".format(str(update.message.from_user.id)))

	# Remove the user from the waiting list and append it to the authorized one
	message = ""

	files.lock.acquire()

	for e in args:
		for user_id in list(files.awaiting):
			if files.awaiting[user_id] == e:
				files.awaiting.pop(user_id)
				files.users[user_id] = []
				bot.sendMessage(user_id, "Sei stato autorizzato.")
				message += e + '\n'
	if message:
		message = "Utenti autorizzati:\n" + message
	else:
		message = "Nessun utente autorizzato"

	files.lock.release()

	context.bot.sendMessage(chat_id=ADMIN, text=message)
	logger.info(message)
	message = None

	files.store(files.users, "users")
	files.store(files.awaiting, "awaiting")

	return

# Create a certificate with a given name
def command_request(update, context):

	files.lock.acquire()

	# Check if the user has subscribed
	if str(update.message.from_user.id) not in files.users:
		update.message.reply_text(text="Non sei autorizzato")
		return

	# Check if he provided a name for the file
	if len(args) != 1:
		update.message.reply_text(text="Specifica solo il nome del certificato")
		return

	# Check if the provided name is permitted
	cert_name = args[0]
	for user in files.users:
		if cert_name in files.users[user]:
			update.message.reply_text(text="Il nome è già in uso")
			return
	files.lock.release()

	if cert_name in ["server", "ta", "car"]:
		update.message.reply_text(text="Il nome è già in uso")
		return

	# Generate a random password for the file, using bash and openssl command
	password = subprocess.getoutput("openssl rand -base64 10")

	# Invoke bash script to create the file
	process = subprocess.Popen(["sudo", "./adder.sh", cert_name, password, update.message.from_user.id])
	process.wait()
	# If exitcode is non zero, fail
	if process.returncode != 0:
		update.message.reply_text(text="Qualcosa è andato storto, riprova")
		return

	files.lock.acquire()

	# Add file name to the list
	files.users[str(update.message.from_user.id)].append(cert_name)

	files.lock.release()

	# Send the file to the user
	update.message.reply_document(open("ovpns/" + cert_name + '.ovpn', 'rb'),\
		caption='Password: ' + password)
	update.message.reply_text(text="Certificato generato")

	logger.info("Certificato %s per l'utente %s aggiunto", cert_name, str(update.message.from_user.id))

	files.store(files.users, "users")

	return

# List a user's certificates
def command_list_certificates(update, context):
	
	files.lock.acquire()

	# Check if the user has subscribed
	if str(update.message.from_user.id) not in files.users:
		update.message.reply_text(text="Non sei autorizzato.")
		return

	# List every certificate he owns
	message = ""
	for cert in files.users[str(update.message.from_user.id)]:
		message += cert + '\n'

	files.lock.release()

	if message:
		message = "Possiedi i seguenti certificati:\n" + message
	else:
		message = "Non hai certificati"
	update.message.reply_text(text=message)
	message = None
	return

# Remove a certificate
def command_revoke(update, context):

	files.lock.acquire()

	# Check if the user has subscribed
	if str(update.message.from_user.id) not in files.users:
		update.message.reply_text(text="Non sei autorizzato")
		return

	# Check if he provided a name for the file
	if len(args) != 1:
		update.message.reply_text(text="Specifica solo il nome del certificato")
		return

	cert_name = args[0]
	# Check if that certificate exists
	if cert_name not in files.users[str(update.message.from_user.id)]:
		update.message.reply_text(text="Certificato non trovato")
		return

	files.lock.release()

	# Remove the certificate
	process = subprocess.Popen(["sudo", "./revoker.sh", cert_name])
	process.wait()
	# If exitcode is non zero, fail
	if process.returncode != 0:
		update.message.reply_text(text="Qualcosa è andato storto, riprova")
		return

	files.users[str(update.message.from_user.id)].remove(cert_name)
	update.message.reply_text(text="Certificato rimosso")
	logger.info("Certificato %s dell'utente %s rimosso", cert_name, update.message.from_user.id)

	files.store(files.users, "users")

	return

def error_logger(bot, update, error):
	"""Log Errors caused by Updates."""
	logger.warning('Update "%s" caused error "%s"', update, error)

def my_idle(updater, stop_signals=(SIGINT, SIGTERM, SIGABRT), update_signals=(SIGUSR1, SIGUSR2)):
	"""Blocks until one of the signals are received and stops the updater.
	Args:
		stop_signals (:obj:`iterable`): Iterable containing signals from the signal module that
			should be subscribed to. Updater.stop() will be called on receiving one of those
			signals. Defaults to (``SIGINT``, ``SIGTERM``, ``SIGABRT``).
	"""

	for sig in stop_signals:
		signal(sig, updater.signal_handler)
	for sig in update_signals:
		signal(sig, updater.user_sig_handler)

	updater.is_idle = True

	while updater.is_idle:
		sleep(1)

def signalHandler(signum, frame):

	if signum != 10:
		return

	logger.info("Received signal {}".format(signum))

	files.lock.acquire()
	try:
		with open("./files/removed.lst", "r") as f:
			removed = f.read().splitlines()
		os.remove("./files/removed.lst")
	except FileNotFoundError:
		removed = []

	for e in files.users:
		files.users[e] = [x for x in files.users[e] if x not in removed]

	files.lock.release()

	files.store(files.users, "users")

	return

def main():

	# Open the files
	files.load_all()

	# Create the Updater and pass it your bot's token.
	updater = Updater(sys.argv[1], user_sig_handler=signalHandler)

	# Get the dispatcher to register handlers
	dp = updater.dispatcher

	dp.add_handler(CommandHandler('start', command_start, Filters.private))
	dp.add_handler(CommandHandler('subscribe', command_subscribe, Filters.private))
	dp.add_handler(CommandHandler('check', command_check, Filters.private))
	dp.add_handler(CommandHandler('approve', command_approve, Filters.private, pass_args=True))
	dp.add_handler(CommandHandler('revoke', command_revoke, Filters.private, pass_args=True))
	dp.add_handler(CommandHandler('list', command_list_certificates, Filters.private))
	dp.add_handler(CommandHandler('request', command_request, Filters.private, pass_args=True))

	# log all errors
	dp.add_error_handler(error_logger)

	# Start the Bot
	updater.start_polling()

	# Run the bot until you press Ctrl-C or the process receives SIGINT,
	# SIGTERM or SIGABRT. This should be used most of the time, since
	# start_polling() is non-blocking and will stop the bot gracefully.
	# SIGUSR1 will call my personal signal handler to update the certificate list
	my_idle(updater)

if __name__ == '__main__':
	ADMIN = sys.argv[2]
	files = files_container()

	# Store current PID
	with open("/run/openvpncertbot/openvpncertbot.pid", "w") as f:
		f.write(str(os.getpid()))

	logger.info("File caricati, admin: %s", ADMIN)
	main()
