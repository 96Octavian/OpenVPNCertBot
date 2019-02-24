#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
"""
Manage your certificate on your VPN with this bot
"""

# TODO: Try to add a Makefile
# TODO: Check openvpn folder structure
# TODO: Add license and credits
# TODO: Allow owner to remove users
# TODO: Improve instructions and info
# TODO: Provide Default.txt
# TODO: extract openvpn server info for client configuration (i.e. to populate Default.txt)
# TODO: Create a Default.txt for every user of the bot

import json
import logging
import os
from systemd.journal import JournaldLogHandler as JournalHandler
import subprocess
import sys

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
		self.users = {}
		self.awaiting = {}

	def load_all(self):

		with open('./files/users.json', 'r') as f:
			self.users = json.load(f)

		with open('./files/awaiting.json', 'r') as f:
			self.awaiting = json.load(f)

		logger.debug("All files opened")
		return

	# To be called whenever a file is modified
	def store(self, file_var, name):
		with open('./files/%s.json' % name, 'w') as json_file:
			json.dump(file_var, json_file, sort_keys=True, indent=4, separators=(',', ': '))
		logger.debug("updated file %s.json", name)
		return

# Check if it is me
def authorized(chat_id):
	if str(chat_id) == personal_id:
		return True
	return False

# First message to be sent
def command_start(bot, update):
	bot.sendMessage(chat_id=update.message.chat_id,\
				 text="Questo bot ti aiuterà a ricevere e rinnovare i tuoi certificati .ovpn.\n\
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
def command_subscribe(bot, update):

	# Check if it has already subscribed
	if str(update.message.from_user.id) in files.users:
		bot.sendMessage(chat_id=update.message.chat_id, text="Sei già iscritto.")
		return

	# Check if it is already in list for approval
	if str(update.message.from_user.id) in files.awaiting:
		bot.sendMessage(chat_id=update.message.chat_id,\
			text="Grazie. La tua iscrizione è in attesa di convalida.")
		return

	# Add him to the waiting list
	files.awaiting[str(update.message.from_user.id)] = update.message.from_user.first_name
	files.store(files.awaiting, "awaiting")
	bot.sendMessage(chat_id=update.message.chat_id,\
		text="Grazie. La tua iscrizione è in attesa di convalida.")
	logger.info("Utente %s in attesa di convalida", str(update.message.from_user.id))

	# Inform me of a new subscriber
	message = "Utenti in attesa:\n"
	for line in files.awaiting:
		message += files.awaiting[line] + '\n'
	bot.sendMessage(personal_id, text=message)
	message = None
	return

# Check pending subscribe requests
def command_check(bot, update):

	# If the sender is not me, discard
	if not authorized(update.message.from_user.id):
		bot.sendMessage(chat_id=update.message.chat_id, text="Non sei autorizzato.")
		return

	# Check if there are awaiting users
	if files.awaiting.keys():
		message = "Utenti in attesa:\n"
		for user_id in files.awaiting:
			message += files.awaiting[user_id] + '\n'
		bot.sendMessage(chat_id=update.message.chat_id, text=message)
		message = None
	else:
		bot.sendMessage(personal_id, "Nessun utente in attesa di approvazione")
	return

# Approve a user(s) subscribe request(s)
def command_approve(bot, update, args):

	# If the sender is not me, discard
	if not authorized(update.message.from_user.id):
		bot.SendMessage(update.message.from_user.id, "Non sei autorizzato.")
		return

	# Remove the user from the waiting list and append it to the authorized one
	message = ""
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

	files.store(files.users, "users")
	files.store(files.awaiting, "awaiting")

	bot.sendMessage(chat_id=personal_id, text=message)
	logger.info(message)
	message = None
	return

# Create a certificate with a given name
def command_request(bot, update, args):

	# Check if the user has subscribed
	if str(update.message.from_user.id) not in files.users:
		bot.sendMessage(chat_id=update.message.chat.id, text="Non sei autorizzato")
		return

	# Check if he provided a name for the file
	if len(args) != 1:
		bot.sendMessage(chat_id=update.message.chat.id, text="Specifica solo il nome del certificato")
		return

	# Check if the provided name is permitted
	cert_name = args[0]
	for user in files.users:
		if cert_name in files.users[user]:
			bot.sendMessage(chat_id=update.message.chat.id, text="Il nome è già in uso")
			return
	if cert_name in ["server", "ta", "car"]:
		bot.sendMessage(chat_id=update.message.chat.id, text="Il nome è già in uso")
		return

	# Add file name to the list
	files.users[str(update.message.from_user.id)].append(cert_name)

	# Generate a random password for the file, using bash and openssl command
	password = subprocess.getoutput("openssl rand -base64 10")

	# Invoke bash script to create the file
	process = subprocess.Popen(["sudo", "./adder.sh", cert_name, password])
	process.wait()
	# If exitcode is non zero, fail
	if process.returncode != 0:
		files.users[str(update.message.from_user.id)].remove(cert_name)
		bot.sendMessage(chat_id=update.message.chat.id,\
				  text="Qualcosa è andato storto, riprova")
		return

	# Send the file to the user
	bot.sendDocument(update.message.chat.id,\
		open("ovpns/" + cert_name + '.ovpn', 'rb'),\
		caption='Password: ' + password)
	bot.sendMessage(update.message.chat.id, text="Certificato generato")

	
	files.store(files.users, "users")
	logger.info("Certificato %s per l'utente %s aggiunto", cert_name, str(update.message.from_user.id))
	return

# List a user's certificates
def command_list_certificates(bot, update):
	# Check if the user has subscribed
	if str(update.message.from_user.id) not in files.users:
		bot.sendMessage(chat_id=update.message.chat.id, text="Non sei autorizzato.")
		return

	# List every certificate he owns
	message = ""
	for cert in files.users[str(update.message.from_user.id)]:
		message += cert + '\n'
	if message:
		message = "Possiedi i seguenti certificati:\n" + message
	else:
		message = "Non hai certificati"
	bot.sendMessage(chat_id=update.message.chat.id, text=message)
	message = None
	return

# Remove a certificate
def command_revoke(bot, update, args):
	# Check if the user has subscribed
	if str(update.message.from_user.id) not in files.users:
		bot.sendMessage(chat_id=update.message.chat.id, text="Non sei autorizzato")
		return

	# Check if he provided a name for the file
	if len(args) != 1:
		bot.sendMessage(chat_id=update.message.chat.id, text="Specifica solo il nome del certificato")
		return

	cert_name = args[0]
	# Check if that certificate exists
	if cert_name not in files.users[str(update.message.from_user.id)]:
		bot.sendMessage(chat_id=update.message.chat.id, text="Certificato non trovato")
		return

	# Remove the certificate
	process = subprocess.Popen(["sudo", "./revoker.sh", cert_name])
	process.wait()
	# If exitcode is non zero, fail
	if process.returncode != 0:
		bot.sendMessage(chat_id=update.message.chat.id, text="Qualcosa è andato storto, riprova")
		return

	files.users[str(update.message.from_user.id)].remove(cert_name)
	files.store(files.users, "users")
	bot.sendMessage(chat_id=update.message.chat.id, text="Certificato rimosso")
	logger.info("Certificato %s dell'utente %s rimosso", cert_name, update.message.from_user.id)
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

	try:
		with open("./files/removed.lst", "r") as f:
			removed = f.read().splitlines()
		os.remove("./files/removed.lst")
	except FileNotFoundError:
		removed = []

	for e in files.users:
		files.users[e] = [x for x in files.users[e] if x not in removed]
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
	personal_id = sys.argv[2]
	files = files_container()

	# Store current PID
	with open("/run/openvpncertbot/openvpncertbot.pid", "w") as f:
		f.write(str(os.getpid()))

	logger.info("File caricati, admin: %s", personal_id)
	main()
